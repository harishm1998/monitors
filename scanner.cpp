// fastsnap_scanner.cpp // High-performance, multithreaded filesystem metadata snapshot tool with full filtering, audit logging, and network export

#define _GNU_SOURCE #include <fcntl.h> #include <sys/syscall.h> #include <sys/stat.h> #include <sys/types.h> #include <sys/statfs.h> #include <linux/stat.h> #include <dirent.h> #include <unistd.h> #include <string.h> #include <stdio.h> #include <errno.h> #include <stdlib.h> #include <stdint.h> #include <vector> #include <string> #include <thread> #include <mutex> #include <iostream> #include <atomic> #include <sstream> #include <regex> #include <map> #include <set> #include <chrono> #include <fstream> #include <arpa/inet.h> #include <netinet/in.h> #include <sys/socket.h>

#define BUF_SIZE 8192

struct FileMeta { std::string path; ino64_t inode; off_t size; uid_t uid; gid_t gid; time_t mtime; bool is_dir; };

std::vector<FileMeta> snapshot; std::mutex snap_mutex; std::atomic<int> active_threads = 0; const int max_threads = std::thread::hardware_concurrency(); std::setstd::string excludes; std::string ext_filter = ""; std::regex name_filter; bool use_regex = false; bool only_files = false; bool only_dirs = false; off_t min_size = 0, max_size = INT64_MAX; time_t min_date = 0, max_date = INT64_MAX; int max_depth = -1; bool json_output = false; bool realtime_output = false; bool monitor_mode = false; bool enable_logging = false; bool network_export = false; std::string audit_log_file = "audit.log"; std::string state_file = "snapshot.state"; std::string export_ip = "127.0.0.1"; int export_port = 9999;

void log_audit(const FileMeta &meta) { if (!enable_logging) return; std::ofstream log(audit_log_file, std::ios::app); log << meta.path << "\t" << meta.inode << "\t" << meta.size << "\t" << meta.uid << ":" << meta.gid << "\t" << meta.mtime << std::endl; }

void export_snapshot(const FileMeta &meta) { if (!network_export) return; int sock = socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) return;

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

bool should_include(const FileMeta &meta) { if (only_files && meta.is_dir) return false; if (only_dirs && !meta.is_dir) return false; if (meta.size < min_size || meta.size > max_size) return false; if (meta.mtime < min_date || meta.mtime > max_date) return false; if (!ext_filter.empty() && !meta.is_dir) { if (meta.path.size() < ext_filter.size() || meta.path.substr(meta.path.size() - ext_filter.size()) != ext_filter) return false; } if (use_regex && !std::regex_search(meta.path, name_filter)) return false; return true; }

void scan_directory(const std::string &path, int depth = 0);

void safe_scan(const std::string &path, int depth) { if (active_threads < max_threads) { active_threads++; std::thread(path, depth { scan_directory(path, depth); active_threads--; }).detach(); } else { scan_directory(path, depth); } }

void scan_directory(const std::string &path, int depth) { if (max_depth != -1 && depth > max_depth) return; for (const auto &ex : excludes) { if (path.find(ex) == 0) return; }

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
            .size = stx.stx_size,
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

void wait_for_threads() { while (active_threads > 0) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); } }

void parse_args(int argc, char *argv[], std::string &root) { for (int i = 1; i < argc; ++i) { std::string arg = argv[i]; if (arg[0] != '-') root = arg; else if (arg == "--json") json_output = true; else if (arg == "--monitor") monitor_mode = true; else if (arg == "--only-files") only_files = true; else if (arg == "--only-dirs") only_dirs = true; else if (arg == "--realtime") realtime_output = true; else if (arg.find("--exclude=") == 0) excludes.insert(arg.substr(10)); else if (arg.find("--maxdepth=") == 0) max_depth = std::stoi(arg.substr(11)); else if (arg.find("--regex=") == 0) { name_filter = std::regex(arg.substr(8)); use_regex = true; } else if (arg.find("--type=") == 0) ext_filter = arg.substr(7); else if (arg.find("--minsize=") == 0) min_size = std::stoll(arg.substr(10)); else if (arg.find("--maxsize=") == 0) max_size = std::stoll(arg.substr(10)); else if (arg.find("--mindate=") == 0) min_date = std::stoll(arg.substr(10)); else if (arg.find("--maxdate=") == 0) max_date = std::stoll(arg.substr(10)); else if (arg == "--log") enable_logging = true; else if (arg == "--export") network_export = true; } }

int main(int argc, char *argv[]) { std::string root; parse_args(argc, argv, root); if (root.empty()) { std::cerr << "Usage: fastsnap_scanner <dir> [--json --monitor --exclude= --maxdepth= --type= --regex= --only-files --only-dirs --realtime --log --export]" << std::endl; return 1; }

auto start = std::chrono::high_resolution_clock::now();
safe_scan(root, 0);
wait_for_threads();
auto end = std::chrono::high_resolution_clock::now();

if (json_output) {
    std::cout << "[\n";
    for (size_t i = 0; i < snapshot.size(); ++i) {
        const auto &e = snapshot[i];
        std::cout << "  {\"path\": \"" << e.path << "\", \"inode\": " << e.inode
                  << ", \"size\": " << e.size << ", \"uid\": " << e.uid
                  << ", \"gid\": " << e.gid << ", \"mtime\": " << e.mtime << "}"
                  << (i + 1 == snapshot.size() ? "\n" : ",\n");
    }
    std::cout << "]\n";
}

std::chrono::duration<double> duration = end - start;
std::cerr << "Scanned in " << duration.count() << " seconds. Files: " << snapshot.size() << std::endl;

return 0;

}

