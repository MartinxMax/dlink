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
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <sstream>
#include <random>
#include <openssl/err.h>


namespace fs = boost::filesystem;
using boost::asio::ip::tcp;
using json = nlohmann::json;

const std::string RESET  = "\033[0m";       
const std::string RED    = "\033[31m";     
const std::string GREEN  = "\033[32m";    
const std::string YELLOW = "\033[33m";     
const std::string BLUE   = "\033[34m";     
const std::string ORANGE = "\033[38;5;214m";  
#define DEFAULT_PORT "10091"  
#define PASSBIT 8         

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
"\033[38;2;128;128;128m https://github.com/MartinxMax   Maptnh@S-H4CK13     Dlink-V2.0 For Linux\033[0m\n";

std::string GLOBAL_KEY;
   
const unsigned char DEFAULT_IV[16] = {14};  

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
std::string encryptAES_CBC(const std::string& plaintext);
std::string decryptAES_CBC(const std::vector<unsigned char>& ciphertext);
std::vector<unsigned char> fromHexString(const std::string& hex) ;
std::string toHexString(const std::vector<unsigned char>& data) ;
std::string generateSecureRandomString();
std::string jsonToString(const json& j, bool pretty = false);
std::string normalizeKey(const std::string& key);
json packet_query(const std::string& path);
bool packet_auth(tcp::socket& socket);
json action_query(const std::string& path, tcp::socket& socket);
json filter_query(const std::string& dir_path, const json& client_query);
bool parse_endpoint(const std::string& endpoint, std::string& ip, std::string& port);
bool verify_auth(tcp::socket& socket);
json read_data(tcp::socket& socket) ;
bool write_data(tcp::socket& socket, const std::string& data);
void show_usage();


void show_usage() {
    std::cout << "Usage: dlink <mode> [options]\n"
              << "\nModes:\n"
              << "  client      Start in client mode\n"
              << "  server      Start in server mode\n"
              << "\nOptions:\n"
              << "  --endpoint <ip:port>   [client] Specify server IP and port [Required]\n"
              << "  --port <port>          [server] Specify port [Default: 10091]\n"
              << "  --path <path>          [client/server] Specify mapping path [Required]\n"
              << "  --reverse              [client/server] Enable reverse connection mode [Optional]\n"
              << "  --key <key>            [client/server] Set encryption key (must be at least " 
              << std::to_string(PASSBIT) << " characters long) [Optional]\n"
              << "  -h, --help             Show this help message\n";
}


std::string normalizeKey(const std::string& key) {
    if (key.size() < 32) {
        return key + std::string(32 - key.size(), '0'); 
    } else {
        return key.substr(0, 32);
    }
}


bool packet_auth(tcp::socket& socket) {
    json packet_authd = {{"auth", GLOBAL_KEY}};
    write_data(socket, packet_authd.dump());
	json status = read_data(socket);
	if (status["status"] == "true") {
		log_info("[SYNC-AUTH] Authentication successful");
		return true;
	} else {
		log_info("[SYNC-AUTH] Authentication failed");
		return false;
	}
}


bool verify_auth(tcp::socket& socket) {
    try {
        json packet = read_data(socket); 
        if (packet.contains("auth") && packet["auth"].is_string()) {
            
			if(packet["auth"] == GLOBAL_KEY){
				json status = {{"status", "true"}};
				write_data(socket, status.dump());
			}else{
				json status = {{"status", "false"}};
				write_data(socket, status.dump());
			}
			 
			return packet["auth"] == GLOBAL_KEY;
        }
    } catch (...) {
        log_info("[ERROR] Authentication packet parsing failed.");
    }
    return false;  
}


std::string jsonToString(const json& j, bool pretty ) {
    return pretty ? j.dump(4) : j.dump();
}


std::string generateSecureRandomString() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789";
    const size_t maxIndex = sizeof(charset) - 2;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, maxIndex);

    std::string randomStr;
    randomStr.reserve(12);

    for (int i = 0; i < 12; ++i) {
        randomStr += charset[dist(gen)];
    }
    return randomStr;
}


std::string toHexString(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}


std::vector<unsigned char> fromHexString(const std::string& hex) {
    if (hex.length() % 2 != 0) return {};
    std::vector<unsigned char> data;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        if (!(ss >> byte)) return {};
        data.push_back(static_cast<unsigned char>(byte));
    }
    return data;
}


std::string encryptAES_CBC(const std::string& plaintext) {
    std::string key = normalizeKey(GLOBAL_KEY);  
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    int paddedSize = plaintext.size() + (AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE));
    std::vector<unsigned char> paddedPlaintext(paddedSize);
    memcpy(paddedPlaintext.data(), plaintext.data(), plaintext.size());
    int paddingLen = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
    for (int i = plaintext.size(); i < paddedSize; i++) {
        paddedPlaintext[i] = paddingLen;
    }   
    std::vector<unsigned char> encrypted(paddedSize + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), DEFAULT_IV) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted.data(), &len, paddedPlaintext.data(), paddedPlaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    encrypted.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return toHexString(encrypted);
}

std::string decryptAES_CBC(const std::string& hexCiphertext) {
    std::string key = normalizeKey(GLOBAL_KEY);  
    std::vector<unsigned char> ciphertext = fromHexString(hexCiphertext);
    if (ciphertext.empty()) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<unsigned char> decrypted(ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), DEFAULT_IV) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + plaintext_len, &len);
    if (ret != 1) {
        log_info("[ERROR] EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    decrypted.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    if (!decrypted.empty()) {
        int padding_len = decrypted.back();
        if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
            bool valid_padding = true;
            for (int i = 0; i < padding_len; ++i) {
                if (decrypted[plaintext_len - 1 - i] != padding_len) {
                    valid_padding = false;
                    break;
                }
            }
            if (valid_padding) {
                decrypted.resize(plaintext_len - padding_len);
            } else {
                log_info("[ERROR] Invalid padding detected!");
                return "";
            }
        } else {
            log_info("[ERROR] Invalid padding value: " + std::to_string(padding_len));
            return "";
        }
    }

    return std::string(decrypted.begin(), decrypted.end());
}

void log_info(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::string color = RESET;
    if (message.find("[ERROR]") == 0) {
        color = RED;
    } else if (message.find("[SYSTEM]") == 0) {
        color = ORANGE;
    } else if (message.find("[SYNC-AUTH]") == 0) {
        color = YELLOW;
    } else if (message.find("[SYNC]") == 0) {
        color = YELLOW;
    } else if (message.find("[SYNC-UPLOAD]") == 0) {
        color = GREEN;
    } else if (message.find("[SYNC-DOWNLOAD]") == 0) {
        color = GREEN;
    } else if (message.find("[SYNC-DELETE]") == 0) {
        color = BLUE;
    }
    std::cout << color << "[" << std::put_time(std::localtime(&in_time_t), "%H:%M:%S") << "] "
               << message << RESET << std::endl;
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
		write_data(socket,jsonToString(delpack,false));
		json status = read_data(socket);
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
		write_data(socket,request); 
		json update = read_data(socket);
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
    for (const auto& file : update["update"]) {
        std::string relative_path = file["path"];
        std::string full_path = (fs::path(base_path) / relative_path).string();

        if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
            log_info("[ERROR] File does not exist: " + full_path);
            continue;
        }

        std::ifstream in_file(full_path, std::ios::binary | std::ios::ate);
        if (!in_file) {
            log_info("[ERROR] Failed to open file: " + full_path);
            continue;
        }

        size_t file_size = in_file.tellg();
        in_file.seekg(0, std::ios::beg);
        std::string file_hash = calculate_hash(full_path);

        json upload_payload = {
            {"upload", {
                {"path", relative_path},
                {"hash", file_hash},
                {"sizeof", file_size}
            }}
        };
        write_data(socket, upload_payload.dump());

        try {
            json response_json = read_data(socket);
            if (response_json["status"] != "true") {
                log_info("[SYNC-UPLOAD] Server rejected file: " + relative_path);
                continue;
            }
        } catch (...) {
            log_info("[SYNC-UPLOAD] Invalid server response, skipping file: " + relative_path);
            continue;
        }

        socket.set_option(boost::asio::socket_base::send_buffer_size(16 * 1024 * 1024));
        socket.set_option(boost::asio::socket_base::receive_buffer_size(16 * 1024 * 1024));

        std::vector<char> buffer(65536);
        size_t total_sent = 0;
        size_t max_retries = 3;
        size_t retry_count = 0;
        auto start_time = std::chrono::high_resolution_clock::now();

        while (total_sent < file_size && retry_count < max_retries) {
            try {
                size_t bytes_read = 0;
                while (in_file.read(buffer.data(), buffer.size()) || in_file.gcount() > 0) {
                    bytes_read = in_file.gcount();
                    total_sent += bytes_read;
                    boost::asio::write(socket, boost::asio::buffer(buffer.data(), bytes_read));

                    double progress = (file_size > 0) ? (double)total_sent / file_size * 100.0 : 0;
                    double uploaded_mb = total_sent / (1024.0 * 1024.0);
                    double total_mb = file_size / (1024.0 * 1024.0);

                    auto elapsed_time = std::chrono::high_resolution_clock::now() - start_time;
                    double elapsed_seconds = std::chrono::duration<double>(elapsed_time).count();
                    double speed = (elapsed_seconds > 0) ? (uploaded_mb / elapsed_seconds) : 0;

                    std::cout << "\r" << GREEN << "[SYNC-UPLOAD] Progress: " 
                              << std::fixed << std::setprecision(2) << progress << "%  "
                              << "(" << uploaded_mb << "MB / " << total_mb << "MB)  "
                              << "Speed: " << std::fixed << std::setprecision(2) << speed << " MB/s"
                              << RESET << std::flush;
                }

                retry_count = 0;
            } catch (const boost::system::system_error& e) {
                log_info("Upload failed, retrying: " + std::string(e.what()));
                ++retry_count;
                if (retry_count >= max_retries) {
                    log_info("Maximum retries reached, aborting upload.");
                    break;
                }
            }
        }

        std::cout << "\n";
        in_file.close();

        try {
            json response_json = read_data(socket);
            if (response_json["status"] != "true") {
                log_info("[SYNC-UPLOAD] Server reported error after receiving file: " + relative_path);
                continue;
            }
        } catch (...) {
            log_info("[SYNC-UPLOAD] Invalid server response after file upload: " + relative_path);
            continue;
        }

        log_info("[SYNC-UPLOAD] File sent successfully: " + relative_path);
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
            if (!packet_auth(socket)){return ;}
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
void download(const std::string& sys_path, const std::string& relative_path, size_t file_size, const std::string& expected_hash, tcp::socket& socket) {
    try {
        std::string save_path = (fs::path(sys_path) / relative_path).string();
        fs::create_directories(fs::path(save_path).parent_path());

        std::ofstream out_file(save_path, std::ios::binary);
        if (!out_file) {
            json response = {{"status", "false"}};  
            write_data(socket, response.dump());
            return;
        }

        socket.set_option(boost::asio::socket_base::send_buffer_size(16 * 1024 * 1024));  
        socket.set_option(boost::asio::socket_base::receive_buffer_size(16 * 1024 * 1024));  

        std::vector<char> buffer(65536);  
        boost::system::error_code error;
        size_t bytes_received = 0;
        auto start_time = std::chrono::high_resolution_clock::now();

        while (bytes_received < file_size) {
            size_t bytes_read = socket.read_some(boost::asio::buffer(buffer), error);
            if (error) {
                log_info("[SYNC-DOWNLOAD] Network error while receiving file.");
                json response = {{"status", "false"}};  
                write_data(socket, response.dump());
                return;
            }

            bytes_received += bytes_read;
            out_file.write(buffer.data(), bytes_read);

            double progress = (file_size > 0) ? (double)bytes_received / file_size * 100.0 : 0;
            double received_mb = bytes_received / (1024.0 * 1024.0);
            double total_mb = file_size / (1024.0 * 1024.0);

            auto elapsed_time = std::chrono::high_resolution_clock::now() - start_time;
            double elapsed_seconds = std::chrono::duration<double>(elapsed_time).count();
            double speed = (elapsed_seconds > 0) ? (received_mb / elapsed_seconds) : 0;

            std::cout << "\r" << "\033[32m" << "[SYNC-DOWNLOAD] Progress: " 
                      << std::fixed << std::setprecision(2) << progress << "%  "
                      << "(" << received_mb << "MB / " << total_mb << "MB)  "
                      << "Speed: " << std::fixed << std::setprecision(2) << speed << " MB/s"
                      << "\033[0m" << std::flush;
        }
        out_file.close();
        std::cout << "\n";
 
        std::string received_hash = calculate_hash(save_path);
        json response = (received_hash == expected_hash) ? json{{"status", "true"}} : json{{"status", "false"}}; 
        write_data(socket, response.dump());

        if (received_hash == expected_hash) {
            log_info("[SYNC-DOWNLOAD] File received successfully: " + save_path);
        } else {
            log_info("[SYNC-DOWNLOAD] Hash mismatch for file: " + save_path);
        }

       

    }
    catch (...) {
        log_info("[SYNC-DOWNLOAD] Exception occurred during file transfer.");
        json response = {{"status", "false"}};  
        write_data(socket, response.dump());
    }
}



json read_data(tcp::socket& socket) {
    boost::asio::streambuf buffer;
    boost::system::error_code error;

    try {
        boost::asio::read_until(socket, buffer, ":SD8A1", error);

        if (error && error != boost::asio::error::eof) {
            log_info("[ERROR] Failed to read data");
            if (socket.is_open()) {
                boost::system::error_code ec;
                socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                socket.close(ec);
            }

            return {};
        }

        std::istream is(&buffer);
        std::string encrypted_data((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());

        std::string delimiter = ":SD8A1";
        size_t pos = encrypted_data.find(delimiter);
        if (pos != std::string::npos) {
            encrypted_data.erase(pos, delimiter.length());
        }


        std::string decrypted_data = decryptAES_CBC(encrypted_data);

        if (decrypted_data.empty()) {
            log_info("[ERROR] Failed to decrypt data");
            if (socket.is_open()) {
                boost::system::error_code ec;
                socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                socket.close(ec);
            }

            return {};
        }

        return json::parse(decrypted_data);

    } catch (const json::exception& e) {
        log_info("[ERROR] JSON parse error");
    } catch (const std::exception& e) {
        log_info("[ERROR] Unexpected error");
    }

    if (socket.is_open()) {
        boost::system::error_code ec;
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }

    return {};
}


bool write_data(tcp::socket& socket, const std::string& data) {
    try {
        if (!socket.is_open()) {
            log_info("[ERROR] Attempted to write to closed socket.");
            return false;  
        }

        std::string encrypted_data = encryptAES_CBC(data) + ":SD8A1";
        boost::asio::write(socket, boost::asio::buffer(encrypted_data));
        return true;  
    } catch (const std::exception& e) {
        log_info("[ERROR] Failed to send data: " + std::string(e.what()));
        boost::system::error_code ec;
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket.close(ec);

        return false; 
    }
}


void sync_ser(tcp::socket& socket, const std::string& path) {
	
	try {
		if (!verify_auth(socket)) {
            log_info("[SYNC-AUTH] Authentication failed");
			return;
		}
        log_info("[SYNC-AUTH] Authentication successful");

		while (socket.is_open()) {
 			 
			json data = read_data(socket);
		 
			json response;

			if (data.contains("query")) {
				json update = filter_query(path, data);
				response = update;
			} else if (data.contains("upload")) {
				response = json{{"status", "true"}};
                log_info("[SYNC-DOWNLOAD] Syncing files");
                if (!write_data(socket, response.dump())) { 
                    break;
                }
				download(path, data["upload"]["path"], data["upload"]["sizeof"], data["upload"]["hash"], socket);
				continue;
			} else if (data.contains("delete")) {
				std::string del_path = data["delete"][0]["path"];
				int result = sys_del(path + '/' + del_path);
				if (result == 400) {
					response = json{{"status", "true"}};
                    log_info("[SYNC-DELETE] Deleted file successfully: " + del_path);
				} else {
					response = json{{"status", "false"}};
                    log_info("[SYNC-DELETE] Failed to delete file: " + del_path);
				}
			} else {
				response = json{{"status", "false"}};
                log_info("[SYNC] Unknown request.");
			}

			write_data(socket, response.dump());
		}
	} catch (const std::exception& e) {
        log_info("[ERROR] Server encountered an issue: " + std::string(e.what()));
	}

    log_info("[SYSTEM] Connection with client has been closed.");
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
                if (!packet_auth(socket)){return ;}
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
    if (argc < 2 || std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
        show_usage();
        return 0;
    }
    std::string mode = argv[1];
    std::string ip, port = DEFAULT_PORT, path;
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
        } else if (arg == "--key" && i + 1 < argc) {
            GLOBAL_KEY = argv[++i];
            if (GLOBAL_KEY.length() < PASSBIT) {
                log_info("[ERROR] Key must be at least " + std::to_string(PASSBIT) + " characters long");
                return 1;
            }
        } else {
            log_info("[ERROR] Unknown argument: " + arg);
            return 1;
        }
    }

    if (mode == "client") {
        if (ip.empty() || port.empty() || path.empty()) {
            log_info("[ERROR] Client mode requires --endpoint and --path");
            show_usage();
            return 1;
        }

        if (GLOBAL_KEY.empty() && !reverse) {
            log_info("[ERROR] Use --key to provide a key > " + std::to_string(PASSBIT) + " characters");
            return 1;
        } else if (GLOBAL_KEY.empty() && reverse) {
            GLOBAL_KEY = generateSecureRandomString();
        }
		log_info("[SYSTEM] Mapping path :  [" + path + "]");
        log_info("[SYSTEM] Sync server key : [" + GLOBAL_KEY + "]");
        start_client(ip, port, path, reverse);
    } else if (mode == "server") {
        if (path.empty()) {
            log_info("[ERROR] Server mode requires --path");
            show_usage();
            return 1;
        }

        if (GLOBAL_KEY.empty()) {
            GLOBAL_KEY = generateSecureRandomString();
        }
		log_info("[SYSTEM] Mapping path :  [" + path + "]");
        log_info("[SYSTEM] Sync server key : [" + GLOBAL_KEY + "]");
        start_server(port, path, reverse);
    } else {
        log_info("[ERROR] Invalid mode");
        show_usage();
        return 1;
    }

    return 0;
}
