// fastsnap_scanner.cpp
// High-performance, multithreaded filesystem metadata snapshot tool with full filtering, audit logging, and network export

#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <linux/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <iostream>
#include <atomic>
#include <sstream>
#include <regex>
#include <map>
#include <set>
#include <chrono>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <filesystem> // C++17 for filesystem checks

#define BUF_SIZE 8192
#define UDP_PORT 9999
#define MAX_UDP_PAYLOAD_SIZE 1400 // Safe size for most networks

// Definition of linux_dirent64 for getdents64 syscall
struct linux_dirent64 {
    ino64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// Simplified metadata structure for network serialization
struct NetworkFileMeta {
    enum Type {
        FILE_META,
        DIR_COUNT,
        END_OF_SCAN
    };
    Type type;
    uint32_t path_len;
    ino64_t inode;
    off_t size;
    time_t mtime;
    uint32_t dir_count; // Used for DIR_COUNT type
};

// Generic FileMeta for local snapshots
struct FileMeta {
    std::string path;
    ino64_t inode;
    off_t size;
    uid_t uid;
    gid_t gid;
    time_t mtime;
    bool is_dir;
};

// Global state
std::vector<FileMeta> snapshot;
std::mutex snap_mutex;
std::atomic<int> active_threads = 0;
const int max_threads = std::thread::hardware_concurrency();
std::set<std::string> excludes;
std::string ext_filter = "";
std::regex name_filter;
bool use_regex = false;
bool only_files = false;
bool only_dirs = false;
off_t min_size = 0, max_size = INT64_MAX;
time_t min_date = 0, max_date = INT64_MAX;
int max_depth = -1;
bool json_output = false;
std::string json_output_file = "";
bool realtime_output = false;
bool monitor_mode = false;
bool enable_logging = false;
bool network_export = false;
bool compare_mode = false;
bool benchmark_mode = false;
bool aggregate_missing = false;
std::string audit_log_file = "audit.log";
std::string state_file = "snapshot.state";
std::string export_ip = "127.0.0.1";
int export_port = 9999;
std::string source_path = "";
std::string dest_path = "";

// New global state for RIDAM mode
bool ridam_server_mode = false;
bool ridam_client_mode = false;
std::string ridam_target_ip = "";
std::map<std::string, FileMeta> local_snapshot_ridam;
std::mutex ridam_snapshot_mutex;
std::condition_variable ridam_scan_done;
std::mutex ridam_scan_done_mutex;
bool ridam_local_scan_finished = false;
std::atomic<int> ridam_discrepancies = 0;


struct Discrepancy {
    std::string file_path;
    std::string reason;
    std::string source_details;
    std::string dest_details;
};

// Logging
void log_audit(const FileMeta &meta) {
    if (!enable_logging) return;
    std::ofstream log(audit_log_file, std::ios::app);
    log << meta.path << "\t" << meta.inode << "\t" << meta.size << "\t"
        << meta.uid << ":" << meta.gid << "\t" << meta.mtime << std::endl;
}

// Network export (TCP) - original feature
void export_snapshot(const FileMeta &meta) {
    if (!network_export) return;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(export_port);
    inet_pton(AF_INET, export_ip.c_str(), &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return;
    }

    std::ostringstream oss;
    oss << meta.path << "\t" << meta.inode << "\t" << meta.size << "\t"
        << meta.uid << ":" << meta.gid << "\t" << meta.mtime << std::endl;

    std::string msg = oss.str();
    send(sock, msg.c_str(), msg.size(), 0);
    close(sock);
}

// New: Network streaming (UDP) functions for RIDAM mode
int udp_sock = -1;
sockaddr_in udp_server_addr{};

void setup_udp_client() {
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        std::cerr << "Error: Could not create UDP socket." << std::endl;
        return;
    }
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_port = htons(UDP_PORT);
    inet_pton(AF_INET, ridam_target_ip.c_str(), &udp_server_addr.sin_addr);
}

void send_udp_packet(const char* data, size_t size) {
    if (udp_sock < 0) return;
    sendto(udp_sock, data, size, 0, (const sockaddr*)&udp_server_addr, sizeof(udp_server_addr));
}

// Inclusion filter
bool should_include(const FileMeta &meta) {
    if (only_files && meta.is_dir) return false;
    if (only_dirs && !meta.is_dir) return false;
    if (meta.size < min_size || meta.size > max_size) return false;
    if (meta.mtime < min_date || meta.mtime > max_date) return false;

    if (!ext_filter.empty() && !meta.is_dir) {
        if (meta.path.size() < ext_filter.size() ||
            meta.path.substr(meta.path.size() - ext_filter.size()) != ext_filter)
            return false;
    }

    if (use_regex && !std::regex_search(meta.path, name_filter))
        return false;

    return true;
}

// Forward declarations for new modes
void scan_directory_ridam_client(const std::string &path, int depth = 0);
void scan_directory_ridam_server_local_scan(const std::string &path, int depth = 0);
void ridam_udp_listener_thread(const std::string& local_root_path);
void scan_directory(const std::string &path, int depth = 0);

// Thread wrapper
void safe_scan(const std::string &path, int depth) {
    if (active_threads < max_threads) {
        active_threads++;
        std::thread([=]() {
            if (ridam_client_mode) {
                scan_directory_ridam_client(path, depth);
            } else if (ridam_server_mode) {
                scan_directory_ridam_server_local_scan(path, depth);
            } else {
                scan_directory(path, depth);
            }
            active_threads--;
        }).detach();
    } else {
        if (ridam_client_mode) {
            scan_directory_ridam_client(path, depth);
        } else if (ridam_server_mode) {
            scan_directory_ridam_server_local_scan(path, depth);
        } else {
            scan_directory(path, depth);
        }
    }
}

// Generic Directory scanning (original function)
void scan_directory(const std::string &path, int depth) {
    if (max_depth != -1 && depth > max_depth) return;

    for (const auto &ex : excludes) {
        if (path.find(ex) == 0) return;
    }

    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;

    char buf[BUF_SIZE];
    struct linux_dirent64 *d;

    while (true) {
        int nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread <= 0) break;

        for (int bpos = 0; bpos < nread;) {
            d = (struct linux_dirent64 *)(buf + bpos);
            std::string name(d->d_name);
            if (name == "." || name == "..") {
                bpos += d->d_reclen;
                continue;
            }

            std::string full_path = path + "/" + name;

            struct statx stx;
            if (statx(fd, d->d_name, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) != 0) {
                bpos += d->d_reclen;
                continue;
            }

            FileMeta meta = {
                .path = full_path,
                .inode = stx.stx_ino,
                .size = static_cast<off_t>(stx.stx_size),
                .uid = stx.stx_uid,
                .gid = stx.stx_gid,
                .mtime = stx.stx_mtime.tv_sec,
                .is_dir = (d->d_type == DT_DIR)
            };

            if (should_include(meta)) {
                {
                    std::lock_guard<std::mutex> lock(snap_mutex);
                    snapshot.push_back(meta);
                }

                if (realtime_output)
                    std::cout << meta.path << std::endl;

                log_audit(meta);
                export_snapshot(meta);
            }

            if (d->d_type == DT_DIR) {
                safe_scan(full_path, depth + 1);
            }

            bpos += d->d_reclen;
        }
    }

    close(fd);
}


// RIDAM Mode Client (Master) - Streams metadata to server
void scan_directory_ridam_client(const std::string &path, int depth) {
    if (max_depth != -1 && depth > max_depth) return;

    for (const auto &ex : excludes) {
        if (path.find(ex) == 0) return;
    }

    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;

    char buf[BUF_SIZE];
    struct linux_dirent64 *d;

    // Check for RIDAM pattern for directory-level optimization
    bool is_ridam_pattern = (path.find("TxSyPzG1") != std::string::npos);

    if (is_ridam_pattern) {
        // Hierarchical optimization: count files in this directory
        int file_count = 0;
        DIR *dir = opendir(path.c_str());
        if (dir) {
            while (readdir(dir)) {
                file_count++;
            }
            closedir(dir);
        }

        NetworkFileMeta dir_packet_meta;
        dir_packet_meta.type = NetworkFileMeta::DIR_COUNT;
        dir_packet_meta.path_len = path.size();
        dir_packet_meta.dir_count = file_count;

        std::vector<char> send_buf;
        send_buf.resize(sizeof(NetworkFileMeta) + path.size());
        memcpy(send_buf.data(), &dir_packet_meta, sizeof(NetworkFileMeta));
        memcpy(send_buf.data() + sizeof(NetworkFileMeta), path.c_str(), path.size());
        send_udp_packet(send_buf.data(), send_buf.size());
    }

    while (true) {
        int nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread <= 0) break;

        for (int bpos = 0; bpos < nread;) {
            d = (struct linux_dirent64 *)(buf + bpos);
            std::string name(d->d_name);
            if (name == "." || name == "..") {
                bpos += d->d_reclen;
                continue;
            }

            std::string full_path = path + "/" + name;
            if (is_ridam_pattern) {
                // If we did a dir count, only stream files and skip subdirectories for now
                if (d->d_type == DT_DIR) {
                    bpos += d->d_reclen;
                    continue;
                }
            }

            struct statx stx;
            if (statx(fd, d->d_name, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) != 0) {
                bpos += d->d_reclen;
                continue;
            }

            NetworkFileMeta file_packet_meta;
            file_packet_meta.type = NetworkFileMeta::FILE_META;
            file_packet_meta.path_len = full_path.size();
            file_packet_meta.inode = stx.stx_ino;
            file_packet_meta.size = static_cast<off_t>(stx.stx_size);
            file_packet_meta.mtime = stx.stx_mtime.tv_sec;

            std::vector<char> send_buf;
            send_buf.resize(sizeof(NetworkFileMeta) + file_packet_meta.path_len);
            memcpy(send_buf.data(), &file_packet_meta, sizeof(NetworkFileMeta));
            memcpy(send_buf.data() + sizeof(NetworkFileMeta), full_path.c_str(), file_packet_meta.path_len);
            send_udp_packet(send_buf.data(), send_buf.size());
            
            if (d->d_type == DT_DIR) {
                safe_scan(full_path, depth + 1);
            }

            bpos += d->d_reclen;
        }
    }
    close(fd);
}

// RIDAM Mode Server (Slave) - Scans locally and receives metadata from master
void scan_directory_ridam_server_local_scan(const std::string &path, int depth) {
    if (max_depth != -1 && depth > max_depth) return;

    for (const auto &ex : excludes) {
        if (path.find(ex) == 0) return;
    }

    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;

    char buf[BUF_SIZE];
    struct linux_dirent64 *d;

    while (true) {
        int nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (nread <= 0) break;

        for (int bpos = 0; bpos < nread;) {
            d = (struct linux_dirent64 *)(buf + bpos);
            std::string name(d->d_name);
            if (name == "." || name == "..") {
                bpos += d->d_reclen;
                continue;
            }

            std::string full_path = path + "/" + name;

            struct statx stx;
            if (statx(fd, d->d_name, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) != 0) {
                bpos += d->d_reclen;
                continue;
            }

            FileMeta meta = {
                .path = full_path,
                .inode = stx.stx_ino,
                .size = static_cast<off_t>(stx.stx_size),
                .uid = stx.stx_uid,
                .gid = stx.stx_gid,
                .mtime = stx.stx_mtime.tv_sec,
                .is_dir = (d->d_type == DT_DIR)
            };

            std::lock_guard<std::mutex> lock(ridam_snapshot_mutex);
            local_snapshot_ridam[full_path] = meta;
            
            if (d->d_type == DT_DIR) {
                safe_scan(full_path, depth + 1);
            }

            bpos += d->d_reclen;
        }
    }
    close(fd);
}

void ridam_udp_listener_thread(const std::string& local_root_path) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error: Could not create UDP socket." << std::endl;
        return;
    }

    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(UDP_PORT);

    if (bind(sockfd, (const sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "Error: Could not bind UDP socket." << std::endl;
        close(sockfd);
        return;
    }
    
    std::vector<char> buffer(MAX_UDP_PAYLOAD_SIZE);
    socklen_t len;
    
    while(true) {
        int n = recvfrom(sockfd, buffer.data(), buffer.size(), MSG_WAITALL, (sockaddr *)&servaddr, &len);
        if (n < 0) continue;

        NetworkFileMeta* packet = reinterpret_cast<NetworkFileMeta*>(buffer.data());
        std::string master_path(buffer.data() + sizeof(NetworkFileMeta), packet->path_len);
        std::string slave_path = local_root_path + master_path.substr(source_path.size());

        if (packet->type == NetworkFileMeta::END_OF_SCAN) {
            std::cerr << "Received end of scan signal from client." << std::endl;
            break;
        }

        std::lock_guard<std::mutex> lock(ridam_snapshot_mutex);
        if (packet->type == NetworkFileMeta::DIR_COUNT) {
            // Directory count check
            // Perform quick local count and compare with packet->dir_count
            // Report discrepancy if counts don't match
        } else {
            // File metadata comparison
            auto it = local_snapshot_ridam.find(slave_path);
            if (it == local_snapshot_ridam.end()) {
                std::cerr << "Discrepancy found: " << slave_path << " missing from slave." << std::endl;
                ridam_discrepancies++;
            } else {
                if (it->second.size != packet->size) {
                    std::cerr << "Discrepancy found: " << slave_path << " size mismatch. Master: " << packet->size << ", Slave: " << it->second.size << std::endl;
                    ridam_discrepancies++;
                }
                if (it->second.mtime != packet->mtime) {
                    std::cerr << "Discrepancy found: " << slave_path << " mtime mismatch. Master: " << packet->mtime << ", Slave: " << it->second.mtime << std::endl;
                    ridam_discrepancies++;
                }
                local_snapshot_ridam.erase(it); // Mark as checked
            }
        }
    }
    close(sockfd);
}

// Wait for threads to finish (original function)
void wait_for_threads() {
    while (active_threads > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// CLI argument parser
void parse_args(int argc, char *argv[], std::vector<std::string> &roots) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] != '-') {
            roots.push_back(arg);
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg.find("--output-json=") == 0) {
            json_output_file = arg.substr(14);
        } else if (arg == "--monitor") {
            monitor_mode = true;
        } else if (arg == "--only-files") {
            only_files = true;
        } else if (arg == "--only-dirs") {
            only_dirs = true;
        } else if (arg == "--realtime") {
            realtime_output = true;
        } else if (arg.find("--exclude=") == 0) {
            excludes.insert(arg.substr(10));
        } else if (arg.find("--maxdepth=") == 0) {
            max_depth = std::stoi(arg.substr(11));
        } else if (arg.find("--regex=") == 0) {
            name_filter = std::regex(arg.substr(8));
            use_regex = true;
        } else if (arg.find("--type=") == 0) {
            ext_filter = arg.substr(7);
        } else if (arg.find("--minsize=") == 0) {
            min_size = std::stoll(arg.substr(10));
        } else if (arg.find("--maxsize=") == 0) {
            max_size = std::stoll(arg.substr(10));
        } else if (arg.find("--mindate=") == 0) {
            min_date = std::stoll(arg.substr(10));
        } else if (arg.find("--maxdate=") == 0) {
            max_date = std::stoll(arg.substr(10));
        } else if (arg == "--log") {
            enable_logging = true;
        } else if (arg == "--export") {
            network_export = true;
        } else if (arg == "--benchmark") {
            benchmark_mode = true;
        } else if (arg == "--aggregate-missing") {
            aggregate_missing = true;
        } else if (arg.find("--compare=") == 0) {
            compare_mode = true;
            std::string paths = arg.substr(10);
            size_t comma_pos = paths.find(',');
            if (comma_pos != std::string::npos) {
                source_path = paths.substr(0, comma_pos);
                dest_path = paths.substr(comma_pos + 1);
            }
        } else if (arg == "--ridam-server") {
            ridam_server_mode = true;
        } else if (arg.find("--ridam-client=") == 0) {
            ridam_client_mode = true;
            ridam_target_ip = arg.substr(15);
        }
    }
}

// Function to generate the comparison report (original)
void generate_comparison_report(const std::map<std::string, FileMeta>& source_map, const std::vector<FileMeta>& dest_snapshot) {
    std::vector<Discrepancy> discrepancies;
    std::set<std::string> matched_dest_files;
    std::set<std::string> aggregated_missing_paths;

    for (const auto& dest_meta : dest_snapshot) {
        std::string relative_path = dest_meta.path.substr(dest_path.length());
        
        if (aggregate_missing) {
            bool is_child_of_missing_dir = false;
            for (const auto& missing_path : aggregated_missing_paths) {
                if (relative_path.find(missing_path) == 0 && relative_path != missing_path) {
                    is_child_of_missing_dir = true;
                    break;
                }
            }
            if (is_child_of_missing_dir) {
                continue;
            }
        }

        auto it = source_map.find(source_path + relative_path);

        if (it == source_map.end()) {
            discrepancies.push_back({relative_path, "Missing from source", "", ""});
            if (aggregate_missing && dest_meta.is_dir) {
                aggregated_missing_paths.insert(relative_path);
            }
        } else {
            const auto& source_meta = it->second;
            if (source_meta.size != dest_meta.size) {
                discrepancies.push_back({
                    relative_path,
                    "Size mismatch",
                    "Size: " + std::to_string(source_meta.size),
                    "Size: " + std::to_string(dest_meta.size)
                });
            }
            if (source_meta.mtime != dest_meta.mtime) {
                discrepancies.push_back({
                    relative_path,
                    "Modification time mismatch",
                    "Mtime: " + std::to_string(source_meta.mtime),
                    "Mtime: " + std::to_string(dest_meta.mtime)
                });
            }
            matched_dest_files.insert(relative_path);
        }
    }

    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (matched_dest_files.find(relative_path) == matched_dest_files.end()) {
            bool is_child_of_missing_dir = false;
            if (aggregate_missing) {
                 for (const auto& missing_path : aggregated_missing_paths) {
                    if (relative_path.find(missing_path) == 0 && relative_path != missing_path) {
                        is_child_of_missing_dir = true;
                        break;
                    }
                }
            }
            if(!is_child_of_missing_dir) {
                discrepancies.push_back({relative_path, "Missing from destination", "", ""});
                 if (aggregate_missing && pair.second.is_dir) {
                     aggregated_missing_paths.insert(relative_path);
                 }
            }
        }
    }

    std::ofstream report_file("compare_f1_f2.json");
    if (report_file.is_open()) {
        report_file << "{\n";
        report_file << "  \"total_discrepancies\": " << discrepancies.size() << ",\n";
        report_file << "  \"discrepancies\": [\n";
        for (size_t i = 0; i < discrepancies.size(); ++i) {
            const auto& d = discrepancies[i];
            report_file << "    {\n";
            report_file << "      \"file_path\": \"" << d.file_path << "\",\n";
            report_file << "      \"reason\": \"" << d.reason << "\",\n";
            report_file << "      \"source_details\": \"" << d.source_details << "\",\n";
            report_file << "      \"dest_details\": \"" << d.dest_details << "\"\n";
            report_file << "    }" << (i + 1 == discrepancies.size() ? "" : ",") << "\n";
        }
        report_file << "  ]\n";
        report_file << "}\n";
        report_file.close();
        std::cout << "Comparison report saved to compare_f1_f2.json" << std::endl;
    } else {
        std::cerr << "Error: Unable to open comparison report file." << std::endl;
    }
}

// Function to print benchmark information (original)
void print_benchmark_info(double duration) {
    std::cerr << "\n--- Benchmark Report ---\n";
    std::string cpu_model, os_name, total_mem;
    int cores = 0;
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                cpu_model = line.substr(line.find(':') + 2);
            }
            if (line.find("cpu cores") != std::string::npos) {
                cores = std::stoi(line.substr(line.find(':') + 2));
            }
        }
    }
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo) {
        std::string line;
        std::getline(meminfo, line);
        total_mem = line.substr(line.find(':') + 2);
    }
    std::ifstream os_release("/etc/os-release");
    if (os_release) {
        std::string line;
        while (std::getline(os_release, line)) {
            if (line.find("PRETTY_NAME") != std::string::npos) {
                os_name = line.substr(line.find('"') + 1, line.length() - line.find('"') - 2);
            }
        }
    }
    std::cerr << "System Hardware/Software:\n";
    std::cerr << "  OS: " << (os_name.empty() ? "N/A" : os_name) << "\n";
    std::cerr << "  CPU: " << (cpu_model.empty() ? "N/A" : cpu_model) << "\n";
    std::cerr << "  Cores/Threads: " << cores << "\n";
    std::cerr << "  Total Memory: " << (total_mem.empty() ? "N/A" : total_mem) << "\n";
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        std::cerr << "\nProgram Resource Usage:\n";
        std::cerr << "  Peak Memory (RSS): " << usage.ru_maxrss / 1024.0 << " MB\n";
        double user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
        double sys_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
        std::cerr << "  CPU Time (User): " << user_time << " seconds\n";
        std::cerr << "  CPU Time (System): " << sys_time << " seconds\n";
        std::cerr << "  Total CPU Time: " << user_time + sys_time << " seconds\n";
    }
    std::cerr << "\nExecution Stats:\n";
    std::cerr << "  Total Time: " << duration << " seconds\n";
    std::cerr << "  Files Scanned: " << snapshot.size() << "\n";
    std::cerr << "-------------------------\n";
}

// Function to check if a path is on a network filesystem
bool is_network_mount(const std::string& path) {
    try {
        std::filesystem::path p(path);
        std::string fstype;
        std::ifstream mounts("/proc/mounts");
        std::string line;
        while(std::getline(mounts, line)) {
            if (line.find(p.string()) != std::string::npos) {
                std::istringstream iss(line);
                std::string dev, mountpoint, type;
                iss >> dev >> mountpoint >> type;
                if (mountpoint == p.string() || p.string().find(mountpoint) == 0) {
                    fstype = type;
                    break;
                }
            }
        }
        return (fstype == "nfs" || fstype == "cifs" || fstype == "smb");
    } catch (...) {
        return false;
    }
}


// Main function
int main(int argc, char *argv[]) {
    std::vector<std::string> roots;
    parse_args(argc, argv, roots);

    auto start = std::chrono::high_resolution_clock::now();

    if (ridam_server_mode) {
        if (roots.size() != 1) {
            std::cerr << "Error: --ridam-server requires a single local path to compare against." << std::endl;
            return 1;
        }
        dest_path = roots[0];
        std::cerr << "Starting RIDAM server listener on port " << UDP_PORT << " for local path: " << dest_path << std::endl;
        
        // Start local scan on a separate thread
        std::thread local_scan_thread(safe_scan, dest_path, 0);
        
        // Start UDP listener
        ridam_udp_listener_thread(dest_path);
        
        local_scan_thread.join();
        
        // Final sanity check for files missing from master
        std::cerr << "\nFinal sanity check for files missing from master:" << std::endl;
        for (const auto& pair : local_snapshot_ridam) {
            std::cerr << "Missing from master: " << pair.first << std::endl;
            ridam_discrepancies++;
        }
        std::cerr << "RIDAM comparison finished with " << ridam_discrepancies << " discrepancies." << std::endl;

    } else if (ridam_client_mode) {
        if (roots.size() != 1) {
            std::cerr << "Error: --ridam-client requires a single path to scan." << std::endl;
            return 1;
        }
        source_path = roots[0];
        setup_udp_client();
        std::cerr << "Starting RIDAM client scan of " << source_path << " and streaming to " << ridam_target_ip << std::endl;
        safe_scan(source_path, 0);
        wait_for_threads();

        NetworkFileMeta end_packet_meta;
        end_packet_meta.type = NetworkFileMeta::END_OF_SCAN;
        send_udp_packet(reinterpret_cast<char*>(&end_packet_meta), sizeof(end_packet_meta));
        std::cerr << "RIDAM client scan finished." << std::endl;

    } else if (compare_mode) {
        if (source_path.empty() || dest_path.empty()) {
            std::cerr << "Error: --compare requires two paths separated by a comma." << std::endl;
            return 1;
        }
        
        // Parallel scan for --compare mode
        std::map<std::string, FileMeta> source_map;
        std::vector<FileMeta> dest_snapshot;

        std::cerr << "Starting parallel scans for comparison." << std::endl;
        std::thread source_scanner([&]() {
            std::cerr << "Scanning source path: " << source_path << std::endl;
            snapshot.clear();
            safe_scan(source_path, 0);
            wait_for_threads();
            for (const auto& meta : snapshot) {
                source_map[meta.path] = meta;
            }
        });
        
        std::thread dest_scanner([&]() {
            std::cerr << "Scanning destination path: " << dest_path << std::endl;
            snapshot.clear();
            safe_scan(dest_path, 0);
            wait_for_threads();
            dest_snapshot = snapshot;
        });

        source_scanner.join();
        dest_scanner.join();

        // Compare and report
        generate_comparison_report(source_map, dest_snapshot);
    } else {
        if (roots.empty()) {
            std::cerr << "Usage: fastsnap_scanner <dir> [dir...] [--ridam-server --ridam-client=IP --json --output-json=file.json --compare=src,dest ...]" << std::endl;
            return 1;
        }

        // Network mount check
        if (!roots.empty() && is_network_mount(roots[0])) {
            std::cerr << "Warning: The path " << roots[0] << " is on a network filesystem. For optimal performance, consider using --ridam-server and --ridam-client modes on separate machines." << std::endl;
        }

        for (const auto& root : roots) {
            safe_scan(root, 0);
        }
        wait_for_threads();

        if (json_output || !json_output_file.empty()) {
            std::ostream* output = &std::cout;
            std::ofstream file_stream;
            if (!json_output_file.empty()) {
                file_stream.open(json_output_file);
                output = &file_stream;
            }
            if (output) {
                *output << "[\n";
                for (size_t i = 0; i < snapshot.size(); ++i) {
                    const auto &e = snapshot[i];
                    *output << "  {\"path\": \"" << e.path << "\", \"inode\": " << e.inode
                            << ", \"size\": " << e.size << ", \"uid\": " << e.uid
                            << ", \"gid\": " << e.gid << ", \"mtime\": " << e.mtime << "}"
                            << (i + 1 == snapshot.size() ? "\n" : ",\n");
                }
                *output << "]\n";
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    if (benchmark_mode) {
        print_benchmark_info(duration.count());
    } else {
        std::cerr << "Scanned in " << duration.count() << " seconds. Files: " << snapshot.size() << std::endl;
    }

    return 0;
}
