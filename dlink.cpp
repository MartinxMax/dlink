/*
███    ███  █████  ██████  ████████ ███    ██ ██   ██ 
████  ████ ██   ██ ██   ██    ██    ████   ██ ██   ██ 
██ ████ ██ ███████ ██████     ██    ██ ██  ██ ███████ 
██  ██  ██ ██   ██ ██         ██    ██  ██ ██ ██   ██ 
██      ██ ██   ██ ██         ██    ██   ████ ██   ██ 
         https://github.com/MartinxMax                                
*/

#include <iostream>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/hex.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <thread>
#include <unordered_map>
#include <chrono>
#include <iomanip>


namespace fs = boost::filesystem;
using boost::asio::ip::tcp;
using json = nlohmann::json;

const char* ascii_art =  
"\033[38;2;255;0;0m        ██████╗       ██╗     ██╗███╗   ██╗██╗  ██╗         \n"
"\033[38;2;255;85;0m        ██╔══██╗      ██║     ██║████╗  ██║██║ ██╔╝         \n"
"\033[38;2;255;170;0m        ██║  ██║█████╗██║     ██║██╔██╗ ██║█████╔╝          \n"
"\033[38;2;255;255;0m        ██║  ██║╚════╝██║     ██║██║╚██╗██║██╔═██╗          \n"
"\033[38;2;170;255;0m        ██████╔╝      ███████╗██║██║ ╚████║██║  ██╗         \n"
"\033[38;2;85;255;0m        ╚═════╝       ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝         \n"
"\033[38;2;0;255;0m                                                            \n"
"\033[38;2;0;255;85m███╗        ███╗      ███╗        ███╗      ███╗        ███╗\n"
"\033[38;2;0;255;170m██╔╝        ╚██║      ██╔╝        ╚██║      ██╔╝        ╚██║\n"
"\033[38;2;0;255;255m██║          ██║█████╗██║          ██║█████╗██║          ██║\n"
"\033[38;2;0;170;255m██║          ██║╚════╝██║          ██║╚════╝██║          ██║\n"
"\033[38;2;0;85;255m███╗███████╗███║      ███╗███████╗███║      ███╗███████╗███║\n"
"\033[38;2;0;0;255m╚══╝╚══════╝╚══╝      ╚══╝╚══════╝╚══╝      ╚══╝╚══════╝╚══╝\n"
"\033[38;2;128;128;128m https://github.com/MartinxMax   Maptnh@S-H4CK13     Dlink-V1.0\033[0m\n";


int sys_del(const std::string& del_path);
void sync_ser(tcp::socket& socket, const std::string& path);
void monitor_directory(const std::string& directory_path, tcp::socket& socket);
void upload(const json& update, tcp::socket& socket, const std::string& base_path);
void start_server(const std::string& port,const std::string& directory_path,bool reverse);
void start_client(const std::string& ip, const std::string& port, const std::string& directory_path, bool reverse) ;
void download(const std::string& sys_path, const std::string& relative_path, size_t file_size, const std::string& expected_hash, tcp::socket& socket);
void log_info(const std::string& message);
int action_del(const std::string& hash, const std::string& file_path, tcp::socket& socket);
std::string calculate_hash(const std::string& file_path);
json packet_query(const std::string& path);
json action_query(const std::string& path, tcp::socket& socket);
json filter_query(const std::string& dir_path, const json& client_query);
bool parse_endpoint(const std::string& endpoint, std::string& ip, std::string& port);


 
void log_info(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&in_time_t), "%H:%M:%S") << "] "
              << message << std::endl;
}


bool parse_endpoint(const std::string& endpoint, std::string& ip, std::string& port) {
    size_t colon_pos = endpoint.find(':');
    if (colon_pos == std::string::npos) {
        log_info("[ERROR] Invalid endpoint format. Expected format: <IP:PORT>");
        return false;
    }
    ip = endpoint.substr(0, colon_pos);
    port = endpoint.substr(colon_pos + 1);
    return true;
}

json filter_query(const std::string& dir_path, const json& client_query) {
	json response;
	response["update"] = json::array();
	json server_files = packet_query(dir_path);
	std::unordered_map<std::string, std::vector<std::string>> server_files_map;
	for (const auto& file : server_files["query"]) {
		std::string hash = file["hash"];
		std::string path = file["path"];
		server_files_map[hash].push_back(path);
	}
	for (const auto& file : client_query["query"]) {
		std::string path = file["path"];
		std::string hash = file["hash"];
        log_info("[SYSTEM] Checking file:"+path+" (hash: "+hash+")");
		if (server_files_map.find(hash) == server_files_map.end() ||
		            std::find(server_files_map[hash].begin(), server_files_map[hash].end(), path) == server_files_map[hash].end()) {
			response["update"].push_back(file);
		} 
	}
	return response;
}

int action_del(const std::string& hash, const std::string& file_path, const std::string& base_path, tcp::socket& socket) {
	try {
		std::string relative_path = fs::relative(file_path, base_path).string();
		json delpack = { {
				"delete", json::array( { { {
							"path", relative_path
						}
						, {
							"hash", hash
						}
					}
				}
				)
			}
		}
		;
		std::string request = delpack.dump();
		boost::asio::write(socket, boost::asio::buffer(request + "\r\n"));
		char response_buf[1024];
		size_t len = socket.read_some(boost::asio::buffer(response_buf));
		std::string response_data(response_buf, len);
		json status = json::parse(response_data);
		if (status["status"] == "true") {
			return 401;
		} else {
			return 402;
		}
	}
	catch (std::exception& e) {
		return 402;
	}
}

std::string calculate_hash(const std::string& file_path) {
	auto start_time = std::chrono::high_resolution_clock::now();
	std::ifstream file(file_path, std::ios::binary);
	if (!file) return "";
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	const EVP_MD* md = EVP_sha256();
	EVP_DigestInit_ex(ctx, md, nullptr);
	char buffer[4096];
	while (file.read(buffer, sizeof(buffer))) {
		EVP_DigestUpdate(ctx, buffer, file.gcount());
	}
	EVP_DigestUpdate(ctx, buffer, file.gcount());
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int length = 0;
	EVP_DigestFinal_ex(ctx, hash, &length);
	EVP_MD_CTX_free(ctx);
	std::string hex_hash;
	boost::algorithm::hex(hash, hash + length, std::back_inserter(hex_hash));
	auto end_time = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> elapsed = end_time - start_time;
	return hex_hash;
}

json packet_query(const std::string& base_path) {
	json result;
	result["query"] = json::array();
	if (!fs::exists(base_path) || !fs::is_directory(base_path)) {
		return result;
	}
	for (const auto& entry : fs::recursive_directory_iterator(base_path)) {
		if (fs::is_regular_file(entry.path())) {
			std::string file_path = entry.path().string();
			std::string file_hash = calculate_hash(file_path);
			if (!file_hash.empty()) {
				std::string relative_path = fs::relative(entry.path(), base_path).string();
				result["query"].push_back( { {
						"path", relative_path
					}
					, {
						"hash", file_hash
					}
				}
				);
			}
		}
	}
	return result;
}

json action_query(const std::string& path, tcp::socket& socket) {
	try {
		json data = packet_query(path);
		std::string request = data.dump();
		boost::asio::write(socket, boost::asio::buffer(request+"\r\n"));
		boost::asio::streambuf buffer;
		boost::asio::read_until(socket, buffer, "}\r\n");
		std::istream is(&buffer);
		std::string response_data((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
		json update = json::parse(response_data);
		if (update.contains("update")) {
			return update;
		} else {
			return json { {
					"status", 402
				}
			}
			;
		}
	}
	catch (std::exception& e) {
        log_info(std::string("[ERROR] Query exception:") + e.what());
		return json { {
				"status", 400
			}
		}
		;
	}
}

void upload(const json& update, tcp::socket& socket, const std::string& base_path) {
	boost::asio::streambuf response_buffer;
	std::istream response_stream(&response_buffer);
	for (const auto& file : update["update"]) {
		std::string relative_path = file["path"];
		std::string full_path = (fs::path(base_path) / relative_path).string();
		if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
            log_info("[ERROR] File does not exist:"+full_path);
			continue;
		}
		std::ifstream in_file(full_path, std::ios::binary | std::ios::ate);
		if (!in_file) {
            log_info("[ERROR] Failed to open file:"+full_path);
			continue;
		}
		size_t file_size = in_file.tellg();
		in_file.close();
		json upload_payload = { {
				"upload", { { {
							"path", relative_path
						}
						,  
                        {
							"hash", file["hash"]
						}
						, 
                        {
							"sizeof", file_size
						}
					}
				}
			}
		}
		;
		std::string request = upload_payload.dump();
		boost::asio::write(socket, boost::asio::buffer(request + "\r\n"));
		boost::asio::read_until(socket, response_buffer, "\r\n");
		std::string server_response;
		std::getline(response_stream, server_response);
		try {
			json response_json = json::parse(server_response);
			if (response_json["status"] != "true") {
                log_info("[SYNC-UPLOAD] Server rejected file: "+relative_path);
				continue;
			}
		}
		catch (...) {
            log_info("[SYNC-UPLOAD] Invalid server response, skipping file:"+relative_path);
			continue;
		}
		std::ifstream file_stream(full_path, std::ios::binary);
		if (!file_stream) {
            log_info("[SYNC-UPLOAD] Failed to open file for sending:"+full_path);
			continue;
		}
		std::vector<char> buffer(4096);
		while (!file_stream.eof()) {
			file_stream.read(buffer.data(), buffer.size());
			std::streamsize bytes_read = file_stream.gcount();
			boost::asio::write(socket, boost::asio::buffer(buffer.data(), bytes_read));
		}
		boost::asio::read_until(socket, response_buffer, "\r\n");
		std::getline(response_stream, server_response);
		try {
			json response_json = json::parse(server_response);
			if (response_json["status"] != "true") {
                log_info("[SYNC-UPLOAD] Server reported error after receiving file:"+relative_path);
				continue;
			}
		}
		catch (...) {
            log_info("[SYNC-UPLOAD] Invalid server response after file upload:"+relative_path);
			continue;
		}
        log_info("[SYNC-UPLOAD] File sent successfully:"+relative_path);
    }
    log_info("[SYNC-UPLOAD] All files sent successfully.");
}

void monitor_directory(const std::string& directory_path, tcp::socket& socket) {
    std::unordered_map<std::string, std::string> file_hash_map;
    auto add_files_to_map = [&file_hash_map](const std::string& path) {
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            if (fs::is_regular_file(entry)) {
                std::string file_path = entry.path().string();
                file_hash_map[file_path] = calculate_hash(file_path);
            }
        }
    };

    add_files_to_map(directory_path);
    json data = action_query(directory_path, socket);
    if (data.contains("update")) {
        log_info("[SYNC] Synchronize local files on the server ...");
        upload(data, socket, directory_path);
    }

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        for (const auto& entry : fs::recursive_directory_iterator(directory_path)) {
            std::string file_path = entry.path().string();

            if (fs::is_symlink(entry)) continue;
            if (file_path.find("~") != std::string::npos || file_path.find(".swp") != std::string::npos) continue;
            if (fs::is_regular_file(entry)) {
                std::string new_hash = calculate_hash(file_path);
                if (!fs::exists(file_path)) continue;
                if (file_hash_map.count(file_path)) {
                    if (file_hash_map[file_path] != new_hash) {
                        json data = action_query(directory_path, socket);
                        if (data.contains("update")) {
                            log_info("[SYNC-UPLOAD] Upload files");
                            upload(data, socket, directory_path);
                        }
                        file_hash_map[file_path] = new_hash;
                    }
                } else {
                    json data = action_query(directory_path, socket);
                    if (data.contains("update")) {
                        log_info("[SYNC-UPLOAD] Upload files");
                        upload(data, socket, directory_path);
                    }
                    file_hash_map[file_path] = new_hash;
                }
            }
        }
        for (auto it = file_hash_map.begin(); it != file_hash_map.end();) {
            if (!fs::exists(it->first)) {
                std::string deleted_file = it->first;
                std::string hash = it->second;
                log_info("[SYNC-DELETE] Delete file:" + deleted_file);
                int status = action_del(hash, deleted_file, directory_path, socket);
                if (status == 401) {
                    log_info("[SYNC-DELETE] Deleted successfully:" + deleted_file);
                } else if (status == 400) {
                    log_info("[SYNC-DELETE] No need to delete files:" + deleted_file);
                } else {
                    log_info("[SYNC-DELETE] Failed to delete file:" + deleted_file);
                }
                it = file_hash_map.erase(it);
            } else {
                ++it;
            }
        }
    }
}



void start_client(const std::string& ip, const std::string& port, const std::string& directory_path, bool reverse) {
	boost::asio::io_context io_context;
	tcp::socket socket(io_context);
	tcp::resolver resolver(io_context);
	try {
		boost::asio::connect(socket, resolver.resolve(ip, port));
		if (reverse) {
			log_info("[SYSTEM] Reverse mode enabled");
			sync_ser(socket,directory_path);
		} else {
			log_info("[SYSTEM] Forward mode enabled");
			monitor_directory(directory_path, socket);
		}
	}
	catch (const std::exception& e) {
        log_info("[ERROR] Client connection failed");
	}
}

int sys_del(const std::string& del_path) {
	namespace fs = std::filesystem;
	try {
		if (fs::exists(del_path)) {
			if (fs::remove(del_path)) {
				return 400;
			} else {
				return 401;
			}
		} else {
			return 401;
		}
	}
	catch (const std::exception& e) {
		return 401;
	}
}

void download(const std::string& sys_path,const std::string& relative_path, size_t file_size, const std::string& expected_hash, tcp::socket& socket) {
	try {
		std::string save_path = (fs::path(sys_path) / relative_path).string();
		fs::create_directories(fs::path(save_path).parent_path());
		std::ofstream out_file(save_path, std::ios::binary);
		if (!out_file) {
			boost::asio::write(socket, boost::asio::buffer(json { {
					"status", "false"
				}
			}
			.dump() + "\r\n"));
			return;
		}
		std::vector<char> buffer(4096);
		size_t received_bytes = 0;
		while (received_bytes < file_size) {
			size_t remaining_bytes = file_size - received_bytes;
			size_t read_size = std::min(buffer.size(), remaining_bytes);
			boost::system::error_code error;
			size_t bytes_read = socket.read_some(boost::asio::buffer(buffer.data(), read_size), error);
			if (error) {
				boost::asio::write(socket, boost::asio::buffer(json { {
						"status", "false"
					}
				}
				.dump() + "\r\n"));
				return;
			}
			out_file.write(buffer.data(), bytes_read);
			received_bytes += bytes_read;
		}
		out_file.close();
		std::string received_hash = calculate_hash(save_path);
		json response = (received_hash == expected_hash) ? json { {
				"status", "true"
			}
		}
		: json { {
				"status", "false"
			}
		}
		;
		boost::asio::write(socket, boost::asio::buffer(response.dump() + "\r\n"));
	}
	catch (...) {
		boost::asio::write(socket, boost::asio::buffer(json { {
				"status", "false"
			}
		}
		.dump() + "\r\n"));
	}
}

void sync_ser(tcp::socket& socket, const std::string& path) {
	try {
		while (true) {
			boost::asio::streambuf buffer;
			size_t bytes_read = boost::asio::read_until(socket, buffer, "}\r\n");
			if (bytes_read == 0) {
                log_info("[SYSTEM] The connection with the client has been aborted");
				break;
			}
			std::istream is(&buffer);
			std::string request_data((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
			json data = json::parse(request_data);
			json response;
			if (data.contains("query")) {
				json update = filter_query(path, data);
				response = update;
			} else if (data.contains("upload")) {
				response = json { {
						"status", "true"
					}
				}
				;
                log_info("[SYNC-DOWNLOAD] Syncing files");
				boost::asio::write(socket, boost::asio::buffer(response.dump() + "\r\n"));
				download(path,data["upload"][0]["path"],data["upload"][0]["sizeof"],data["upload"][0]["hash"],socket);
				continue;
			} else if (data.contains("delete")) {
				std::string del_path = data["delete"][0]["path"];
				int result = sys_del(path+'/'+del_path);
				if (result == 400) {
					response = json { {
							"status", "true"
						}
					}
					;
                    log_info("[SYNC-DELETE] Delete file successfully:"+del_path);
				} else {
					response = json { {
							"status", "false"
						}
					}
					;
				}
			} else {
				response = json { {
						"status", "false"
					}
				};
                log_info("[SYNC-DELETE] Failed to delete file");
			}
			std::string response_str = response.dump() + "\r\n";
			boost::asio::write(socket, boost::asio::buffer(response_str));
		}
	}
	catch (const std::exception& e) {
        log_info(std::string("[ERROR] There was a problem with the server processing the message") + e.what());
	}
    log_info("[SYSTEM] The connection with the client has been aborted");
}

void start_server(const std::string& port,const std::string& directory_path,bool reverse) {
	try {
		boost::asio::io_context io_context;

        unsigned short port_num = static_cast<unsigned short>(std::stoi(port));
		tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port_num));
        log_info("[SYSTEM] D-link service open on [0.0.0.0:"+port+"]");
        if(reverse){
            log_info("[SYSTEM] Reverse mode enabled");
        }else{
            log_info("[SYSTEM] Forward mode enabled");
        }
		while (true) {
			tcp::socket socket(io_context);
			acceptor.accept(socket);
            log_info("[SYSTEM] D-link client connected...");
			if (reverse) {
				monitor_directory(directory_path, socket);
			} else {
				std::thread([sock = std::make_unique<tcp::socket>(std::move(socket)), path = std::move(directory_path)]() mutable {
					sync_ser(*sock, path);
				}
				).detach();
			}
		}
	}
	catch (const std::exception& e) {
        log_info(std::string("[ERROR] D-link D-Link cannot start due to force majeure:") + e.what());
	}
}

int main(int argc, char* argv[]) {
    std::cout << ascii_art << std::endl;

    if (argc < 4) {
        std::cerr << "Usage:\n";
        std::cerr << "  Client: " << argv[0] << " client --endpoint <IP:PORT> --path <DIR> [--reverse]\n";
        std::cerr << "  Server: " << argv[0] << " server --port <PORT> --path <DIR> [--reverse]\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string ip, port, path;
    bool reverse = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--endpoint" && i + 1 < argc) {
            std::string endpoint = argv[++i];
            if (!parse_endpoint(endpoint, ip, port)) {
                return 1;
            }
        } else if (arg == "--port" && i + 1 < argc) {
            port = argv[++i];
        } else if (arg == "--path" && i + 1 < argc) {
            path = argv[++i];
        } else if (arg == "--reverse") {
            reverse = true;
        } else {
            log_info("[ERROR] Unknown argument:"+arg);
            return 1;
        }
    }

    if (path.empty() || ((mode == "client" && (ip.empty() || port.empty())) || (mode == "server" && port.empty()))) {
        log_info("[ERROR] Missing required arguments");
        return 1;
    }

    if (mode == "client") {
        start_client(ip, port, path, reverse);
    } else if (mode == "server") {
        start_server(port, path, reverse);
    } else {
        log_info("[ERROR] Invalid mode");
        return 1;
    }
    return 0;
}