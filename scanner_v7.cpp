// fastsnap_scanner.cpp
// High-performance, multithreaded filesystem metadata snapshot tool with full filtering, audit logging, and network export
#include <condition_variable>
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



#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <nlohmann/json.hpp>

using json = nlohmann::json;



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
std::vector<std::thread> threads;
std::mutex thread_counter_mutex;
std::mutex local_map_mutex; // Make the mutex a global variable
//int active_threads = 0;
std::mutex mtx;
std::condition_variable cv;
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
std::set<std::string> missing_directories; 

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
// New: Forward declaration for the optimized comparison scan
//void scan_directory_for_compare(const std::string &path, int depth, std::map<std::string, FileMeta>& local_map);
void scan_directory_for_compare(const std::string &path, int depth, std::map<std::string, FileMeta>& local_map, std::mutex& map_mutex);


// Thread wrapper
void safe_scan(const std::string &path, int depth) {
    // Lock the mutex to safely check and increment the thread counter
    std::lock_guard<std::mutex> lock(thread_counter_mutex);
    
    if (active_threads < max_threads) {
        active_threads++;
        
        // Use a lambda to capture variables by value ([=])
        auto scan_task = [=]() {
            if (ridam_client_mode) {
                scan_directory_ridam_client(path, depth);
            } else if (ridam_server_mode) {
                scan_directory_ridam_server_local_scan(path, depth);
            } else {
                scan_directory(path, depth);
            }
            
            // Lock the mutex again to safely decrement the counter
            std::lock_guard<std::mutex> lock(thread_counter_mutex);
            active_threads--;
        };
        
        // Push the new thread into the vector
        threads.emplace_back(scan_task);

    } else {
        // If max_threads is reached, run the task synchronously in the current thread
        if (ridam_client_mode) {
            scan_directory_ridam_client(path, depth);
        } else if (ridam_server_mode) {
            scan_directory_ridam_server_local_scan(path, depth);
        } else {
            scan_directory(path, depth);
        }
    }
}

// Thread wrapper specifically for comparison mode. Note this uses a different map.

void safe_scan_for_compare(const std::string &path, int depth, std::map<std::string, FileMeta>& local_map, std::mutex& map_mutex) {
    if (active_threads < max_threads) {
        // Correct atomic increment.
        // It's better to use std::atomic::fetch_add for clarity and correctness
        // in multi-threaded scenarios.
        active_threads.fetch_add(1);
        
        // The lambda must capture the mutex by reference
        // Use [=, &local_map, &map_mutex] to capture
        // path and depth by value, and local_map and map_mutex by reference.
        std::thread([=, &local_map, &map_mutex]() {
            scan_directory_for_compare(path, depth, local_map, map_mutex);
            
            // Correct atomic decrement
            active_threads.fetch_sub(1);
        }).detach();
    } else {
        // Synchronous call. The mutex is passed by reference.
        scan_directory_for_compare(path, depth, local_map, map_mutex);
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

// New: Directory scanning function for compare mode, to fill a map


// Change the signature to accept a mutex by reference
void scan_directory_for_compare(const std::string &path, int depth, std::map<std::string, FileMeta>& local_map, std::mutex& map_mutex) {
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

            // Lock the mutex before modifying the map
            if (should_include(meta)) {
                // The mutex must be passed by reference from the caller.
                std::lock_guard<std::mutex> lock(map_mutex);
                local_map[full_path] = meta;
            }

            if (d->d_type == DT_DIR) {
                // The recursive call must also pass the mutex by reference
                safe_scan_for_compare(full_path, depth + 1, local_map, map_mutex);
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

void wait_for_threads__() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, []{ return active_threads == 0; });
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
        if (relative_path.length() > 0 && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);
        }
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
	 if (relative_path.length() > 0 && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);
        }
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

void compare_ridam_style_v1() {
    std::map<std::string, FileMeta> source_map;
    std::map<std::string, FileMeta> dest_map;
    std::vector<Discrepancy> discrepancies;
    std::mutex map_mutex;
    std::cerr << "Starting parallel scans for comparison." << std::endl;

    // Scan both sides in parallel using the new, map-filling scan function
    std::thread source_scanner([&]() {
        std::cerr << "Scanning source path: " << source_path << std::endl;
        safe_scan_for_compare(source_path, 0, source_map, map_mutex);
        std::cerr << "Source scan completed for path: " << source_path << std::endl;
        wait_for_threads();
    });

    std::thread dest_scanner([&]() {
        std::cerr << "Scanning destination path: " << dest_path << std::endl;
        safe_scan_for_compare(dest_path, 0, dest_map, map_mutex);
        std::cerr << "Destination scan completed for path: " << dest_path << std::endl;
        wait_for_threads();
    });

    // Ensure both threads have finished before continuing
    source_scanner.join();
    dest_scanner.join();

    std::cerr << "\nStarting two-layered comparison...\n";

    // Normalize paths (remove any trailing slashes, standardize separators)
    auto normalize_path = [](const std::string& path) -> std::string {
        std::string normalized = path;
        if (normalized.back() == '/') {
            normalized.pop_back();  // Remove trailing slash
        }
        return normalized;
    };

    // Helper function to check if the path exists in source (stopping at first missing directory)
    auto check_missing_hierarchy = [&](const std::string& relative_path, const std::map<std::string, FileMeta>& map) -> bool {
        std::string full_path = normalize_path(source_path + "/" + relative_path);
        bool missing = map.find(full_path) == map.end();
        if (missing) {
            std::cerr << "Missing hierarchy: " << full_path << std::endl;
        }
        return missing;
    };

    // Track missing directories to avoid checking files under them
    std::set<std::string> missing_directories;

    // Helper function to check if the path is under any missing directory
    auto is_under_missing_directory = [&](const std::string& relative_path) -> bool {
        for (const auto& missing_dir : missing_directories) {
            if (relative_path.find(missing_dir) == 0) {
                return true;  // Path is under a missing directory
            }
        }
        return false;
    };

    // Layer 1: Check for existence (missing files/folders)
    std::cerr << "Starting Layer 1: Checking for missing files/folders..." << std::endl;

    for (const auto& pair : dest_map) {
        std::string relative_path = pair.first.substr(dest_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Skip files under missing directories
        if (is_under_missing_directory(relative_path)) {
            continue;
        }

        // Check if directory is missing in the source
        if (check_missing_hierarchy(relative_path, source_map)) {
            discrepancies.push_back({relative_path, "Missing from source", "", ""});
            missing_directories.insert(relative_path);  // Mark the directory as missing
            std::cerr << "Directory missing from source: " << relative_path << std::endl;
        }
    }

    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Skip files under missing directories
        if (is_under_missing_directory(relative_path)) {
            continue;
        }

        // Check if directory is missing in the destination
        if (check_missing_hierarchy(relative_path, dest_map)) {
            discrepancies.push_back({relative_path, "Missing from destination", "", ""});
            missing_directories.insert(relative_path);  // Mark the directory as missing
            std::cerr << "Directory missing from destination: " << relative_path << std::endl;
        }
    }

    std::cerr << "Layer 1 complete. Checking for size discrepancies..." << std::endl;

    // Layer 2: Check for size discrepancies (if needed)
    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Skip files under missing directories
        if (is_under_missing_directory(relative_path)) {
            continue;
        }

        auto dest_it = dest_map.find(normalize_path(dest_path + "/" + relative_path));
        if (dest_it != dest_map.end()) {
            const auto& source_meta = pair.second;
            const auto& dest_meta = dest_it->second;

            // Compare file sizes and log discrepancies
            if (source_meta.size != dest_meta.size) {
                discrepancies.push_back({
                    relative_path,
                    "Size mismatch",
                    "Source size: " + std::to_string(source_meta.size),
                    "Dest size: " + std::to_string(dest_meta.size)
                });
                std::cerr << "Size mismatch for file: " << relative_path << std::endl;
            }
        }
    }

    std::cerr << "Layer 2 complete. Total discrepancies found: " << discrepancies.size() << std::endl;

    // Write the report
    std::ofstream report_file("compare_report.json");
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
        std::cout << "Comparison report saved to compare_report.json" << std::endl;
    } else {
        std::cerr << "Error: Unable to open comparison report file." << std::endl;
    }
}


void filter_redundant_entries___(std::vector<Discrepancy>& discrepancies) {
    std::set<std::string> missing_paths;

    // Step 1: Identify all parent paths that are missing
    for (const auto& discrepancy : discrepancies) {
        if (discrepancy.reason == "Missing from source" || discrepancy.reason == "Missing from destination") {
            // Add a trailing slash to treat it as a directory prefix
            std::string path_prefix = discrepancy.file_path;
            if (!path_prefix.empty() && path_prefix.back() != '/') {
                path_prefix += '/';
            }
            missing_paths.insert(path_prefix);
        }
    }

    // Step 2: Filter out the children of the missing paths using the erase-remove idiom
    discrepancies.erase(
        std::remove_if(discrepancies.begin(), discrepancies.end(),
                       [&](const Discrepancy& d) {
                           // Check if this discrepancy's path is a child of any missing path
                           for (const auto& missing_path_prefix : missing_paths) {
                               // Check if the file_path starts with the missing_path_prefix
                               if (d.file_path.size() > missing_path_prefix.size() &&
                                   d.file_path.rfind(missing_path_prefix, 0) == 0) {
                                   return true; // Mark for removal
                               }
                           }
                           return false; // Keep this discrepancy
                       }),
        discrepancies.end());
}
// Function to filter out redundant child entries based on missing parent paths
void filter_redundant_entries__(std::vector<Discrepancy>& discrepancies) {
    std::set<std::string> missing_paths; // To track missing paths and avoid redundancies

    // Step 1: Identify all parent paths that are missing (i.e., where `reason` is "Missing from source" or "Missing from destination")
    for (auto it = discrepancies.begin(); it != discrepancies.end(); ) {
        const auto& discrepancy = *it;

        // If the discrepancy reason is a missing path (either source or destination)
        if (discrepancy.reason == "Missing from source" || discrepancy.reason == "Missing from destination") {
            // Insert the missing path into the set
            missing_paths.insert(discrepancy.file_path);

            // We continue to the next discrepancy after marking this as missing
            ++it;
        } else {
            // Keep the discrepancy if it's not a missing one
            ++it;
        }
    }

    // Step 2: Filter out the children of the missing paths
    for (auto it = discrepancies.begin(); it != discrepancies.end(); ) {
        const auto& discrepancy = *it;

        // Check if the parent directory of this discrepancy is already in the `missing_paths` set
        bool is_child_of_missing_path = false;
        for (const auto& missing_path : missing_paths) {
            if (discrepancy.file_path.find(missing_path) == 0 && discrepancy.file_path != missing_path) {
                is_child_of_missing_path = true;
                break;
            }
        }

        // If this path is a child of a missing path, remove it
        if (is_child_of_missing_path) {
            it = discrepancies.erase(it);  // Remove the discrepancy and move to the next
        } else {
            ++it; // Otherwise, keep the discrepancy
        }
    }
}



void compare_ridam_style() {
    std::map<std::string, FileMeta> source_map;
    std::map<std::string, FileMeta> dest_map;
    std::vector<Discrepancy> discrepancies;
    std::mutex map_mutex;
    std::cerr << "Starting parallel scans for comparison." << std::endl;

    // Scan both sides in parallel using the new, map-filling scan function
    std::thread source_scanner([&]() {
        std::cerr << "Scanning source path: " << source_path << std::endl;
        safe_scan_for_compare(source_path, 0, source_map, map_mutex);
        wait_for_threads();
    });

    std::thread dest_scanner([&]() {
        std::cerr << "Scanning destination path: " << dest_path << std::endl;
        safe_scan_for_compare(dest_path, 0, dest_map, map_mutex);
        wait_for_threads();
    });

    source_scanner.join();
    dest_scanner.join();

    std::cerr << "\nStarting two-layered comparison...\n";

    // Normalize paths (remove any trailing slashes, standardize separators)
    auto normalize_path = [](const std::string& path) -> std::string {
        std::string normalized = path;
        if (normalized.back() == '/') {
            normalized.pop_back();  // Remove trailing slash
        }
        return normalized;
    };

    // Helper function to check if the path exists in source (stopping at first missing directory)
    auto check_missing_hierarchy = [&](const std::string& relative_path, const std::map<std::string, FileMeta>& map) -> bool {
        std::string full_path = normalize_path(source_path + "/" + relative_path);
        return map.find(full_path) == map.end();
    };

    std::set<std::string> checked_directories; // To avoid checking files under missing directories

    // Layer 1: Check for existence (missing files/folders)
    for (const auto& pair : dest_map) {
        std::string relative_path = pair.first.substr(dest_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Check if directory is missing in the source
        if (check_missing_hierarchy(relative_path, source_map)) {
            discrepancies.push_back({relative_path, "Missing from source", "", ""});
            checked_directories.insert(relative_path);  // Mark the directory as checked
        }
    }

    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Check if directory is missing in the destination
        if (check_missing_hierarchy(relative_path, dest_map)) {
            discrepancies.push_back({relative_path, "Missing from destination", "", ""});
            checked_directories.insert(relative_path);  // Mark the directory as checked
        }
    }

    // Layer 2: Check for size discrepancies (if needed)
    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // Remove leading '/'
        }

        // Skip files in checked directories
        if (checked_directories.find(relative_path) != checked_directories.end()) {
            continue;
        }

        auto dest_it = dest_map.find(normalize_path(dest_path + "/" + relative_path));
        if (dest_it != dest_map.end()) {
            const auto& source_meta = pair.second;
            const auto& dest_meta = dest_it->second;

            // Compare file sizes and log discrepancies
            if (source_meta.size != dest_meta.size) {
                discrepancies.push_back({
                    relative_path,
                    "Size mismatch",
                    "Source size: " + std::to_string(source_meta.size),
                    "Dest size: " + std::to_string(dest_meta.size)
                });
            }
        }
    }
    //filter_redundant_entries(discrepancies);
    // Write the report
    std::ofstream report_file("compare_report.json");
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
        std::cout << "Comparison report saved to compare_report.json" << std::endl;
    } else {
        std::cerr << "Error: Unable to open comparison report file." << std::endl;
    }
}


void filter_redundant_entries(std::vector<Discrepancy>& discrepancies) {
    std::set<std::string> seen_paths;  // To track processed paths
    std::vector<Discrepancy> filtered_discrepancies;

    for (const auto& d : discrepancies) {
        std::string path = d.file_path;

        // Check if any previously processed path is a prefix of the current path
        bool is_redundant = false;
        for (const auto& seen_path : seen_paths) {
            if (path.find(seen_path) == 0) {  // If the current path starts with a seen path
                is_redundant = true;
                break;
            }
        }

        if (is_redundant) {
            continue;  // Skip this entry as it's redundant
        }

        // Add this path to the seen paths
        seen_paths.insert(path);
        filtered_discrepancies.push_back(d);
    }

    discrepancies = filtered_discrepancies;  // Update the discrepancies with the filtered ones
}

void process_and_filter_report(const std::string& report_file_path) {
    // Step 1: Read the existing report
    std::ifstream report_file(report_file_path);
    if (!report_file.is_open()) {
        std::cerr << "Error: Unable to open report file for reading." << std::endl;
        return;
    }

    json report_data;
    report_file >> report_data;
    report_file.close();

    // Step 2: Extract discrepancies from the original report
    std::vector<Discrepancy> discrepancies;
    for (const auto& item : report_data["discrepancies"]) {
        discrepancies.push_back({
            item["file_path"].get<std::string>(),
            item["reason"].get<std::string>(),
            item["source_details"].get<std::string>(),
            item["dest_details"].get<std::string>()
        });
    }

    // Step 3: Filter out redundant entries
    filter_redundant_entries(discrepancies);

    // Step 4: Write the filtered discrepancies to the report
    std::ofstream output_report_file("filtered_compare_report.json");
    if (output_report_file.is_open()) {
        output_report_file << "{\n";
        output_report_file << "  \"total_discrepancies\": " << discrepancies.size() << ",\n";
        output_report_file << "  \"discrepancies\": [\n";
        for (size_t i = 0; i < discrepancies.size(); ++i) {
            const auto& d = discrepancies[i];
            output_report_file << "    {\n";
            output_report_file << "      \"file_path\": \"" << d.file_path << "\",\n";
            output_report_file << "      \"reason\": \"" << d.reason << "\",\n";
            output_report_file << "      \"source_details\": \"" << d.source_details << "\",\n";
            output_report_file << "      \"dest_details\": \"" << d.dest_details << "\"\n";
            output_report_file << "    }" << (i + 1 == discrepancies.size() ? "" : ",") << "\n";
        }
        output_report_file << "  ]\n";
        output_report_file << "}\n";
        output_report_file.close();
        std::cout << "Filtered comparison report saved to filtered_compare_report.json" << std::endl;
    } else {
        std::cerr << "Error: Unable to open output report file." << std::endl;
    }
}



void compare_ridam_style__() {
    std::map<std::string, FileMeta> source_map;
    std::map<std::string, FileMeta> dest_map;
    std::vector<Discrepancy> discrepancies;
    std::mutex map_mutex;
    std::cerr << "Starting parallel scans for comparison." << std::endl;

    // Scan both sides in parallel using the new, map-filling scan function
    std::thread source_scanner([&]() {
        std::cerr << "Scanning source path: " << source_path << std::endl;
        safe_scan_for_compare(source_path, 0, source_map, map_mutex);
        wait_for_threads();
    });

    std::thread dest_scanner([&]() {
        std::cerr << "Scanning destination path: " << dest_path << std::endl;
        safe_scan_for_compare(dest_path, 0, dest_map, map_mutex);
        wait_for_threads();
    });

    source_scanner.join();
    dest_scanner.join();

    std::cerr << "\nStarting two-layered comparison...\n";

    // Helper function to check if the path exists in source and stop at the first missing directory
    auto check_missing_hierarchy = [&](const std::string& relative_path) -> bool {
        size_t pos = 0;
        // Traverse the directory structure, checking each level of the path
        while ((pos = relative_path.find('/', pos)) != std::string::npos) {
            std::string sub_path = relative_path.substr(0, pos);
            if (source_map.find(source_path + "/" + sub_path) == source_map.end()) {
                return true; // First missing directory found
            }
            ++pos; // move past the current '/' to the next part of the path
        }
        // At the last part (file or last folder), check if the file exists
        return source_map.find(source_path + "/" + relative_path) == source_map.end();
    };

    // Layer 1: Check for existence (missing files/folders)
    for (const auto& pair : dest_map) {
        std::string relative_path = pair.first.substr(dest_path.length());
        if (relative_path.length() > 0 && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // remove leading '/'
        }

        // Check for missing directories in source without marking descendants
        if (check_missing_hierarchy(relative_path)) {
            discrepancies.push_back({relative_path, "Missing from source", "", ""});
        }
    }

    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path.length() > 0 && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // remove leading '/'
        }

        // Check for missing directories in destination without marking descendants
        if (check_missing_hierarchy(relative_path)) {
            discrepancies.push_back({relative_path, "Missing from destination", "", ""});
        }
    }

    // Layer 2: Check for size discrepancies (if needed)
    for (const auto& pair : source_map) {
        std::string relative_path = pair.first.substr(source_path.length());
        if (relative_path.length() > 0 && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);  // remove leading '/'
        }

        auto dest_it = dest_map.find(dest_path + "/" + relative_path);
        if (dest_it != dest_map.end()) {
            const auto& source_meta = pair.second;
            const auto& dest_meta = dest_it->second;

            if (source_meta.size != dest_meta.size) {
                discrepancies.push_back({
                    relative_path,
                    "Size mismatch",
                    "Source size: " + std::to_string(source_meta.size),
                    "Dest size: " + std::to_string(dest_meta.size)
                });
            }
        }
    }

    // Write the report
    std::ofstream report_file("compare_report.json");
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
        std::cout << "Comparison report saved to compare_report.json" << std::endl;
    } else {
        std::cerr << "Error: Unable to open comparison report file." << std::endl;
    }
    // After report creation, filter out redundant child paths
    filter_redundant_entries(discrepancies);

    // Optional: If you want to save the filtered discrepancies into another file or handle them further
    std::ofstream filtered_report_file("filtered_compare_report.json");
    if (filtered_report_file.is_open()) {
        filtered_report_file << "{\n";
        filtered_report_file << "  \"total_discrepancies\": " << discrepancies.size() << ",\n";
        filtered_report_file << "  \"discrepancies\": [\n";
        for (size_t i = 0; i < discrepancies.size(); ++i) {
            const auto& d = discrepancies[i];
            filtered_report_file << "    {\n";
            filtered_report_file << "      \"file_path\": \"" << d.file_path << "\",\n";
            filtered_report_file << "      \"reason\": \"" << d.reason << "\",\n";
            filtered_report_file << "      \"source_details\": \"" << d.source_details << "\",\n";
            filtered_report_file << "      \"dest_details\": \"" << d.dest_details << "\"\n";
            filtered_report_file << "    }" << (i + 1 == discrepancies.size() ? "" : ",") << "\n";
        }
        filtered_report_file << "  ]\n";
        filtered_report_file << "}\n";
        filtered_report_file.close();
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
        
        // Calling the new RIDAM-style comparison function
        compare_ridam_style();
        std::string report_file_path = "compare_report.json";
        process_and_filter_report(report_file_path);

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
