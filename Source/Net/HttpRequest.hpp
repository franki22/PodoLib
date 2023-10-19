#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <WinSock2.h>
#include <WS2tcpip.h>

//#include "stringhelper.hpp"

#pragma comment(lib, "ws2_32.lib")

namespace net
{
	class HttpRequest
	{
	private:
		static std::vector<std::string> GetDefaultHeader()
		{
			std::vector<std::string> headers;

			return headers;
		}

		static std::string GetHeaderKey(std::string header)
		{
			std::string key;

			size_t pos = header.find(":", 0);
			if (std::string::npos != pos)
			{
				key = header.substr(0, pos - 1);
			}

			return key;
		}

		static bool ReplaceHeader(std::vector<std::string>& src, std::string& dst)
		{
			bool result = false;
			std::string src_key;
			std::string dst_key;

			size_t pos = dst.find(":", 0);
			if (std::string::npos != pos)
			{
				dst_key = dst.substr(0, pos - 1);
				//helper::stringhelper::trim(dst_key);
			}

			// up to C++11
			//std::vector<std::string>::iterator it = std::find_if(src.begin(), src.end(),
			//	[&](auto& val)
			//{
			//	src_key = GetHeaderKey(val);
			//	//helper::stringhelper::trim(src_key);
			//	return src_key == dst_key;
			//}
			//);

			//if (it != src.end())
			//{
			//	(*it) = dst;
			//	result = true;
			//}

			std::vector<std::string>::iterator it = src.begin();
			for (it; it != src.end(); ++it)
			{
				src_key = GetHeaderKey((*it));
				if (src_key == dst_key)
				{
					(*it) = dst;
					result = true;
				}
			}

			return result;
		}

		static void MergeHeader(std::vector<std::string>& src, std::vector<std::string> append)
		{
			std::vector<std::string> headers;

			std::vector<std::string>::iterator it = append.begin();
			for (it; it != append.end(); ++it)
			{
				if (!ReplaceHeader(src, (*it)))
				{
					src.push_back((*it));
				}
			}
		}

		static bool IsChunked(std::string& packet)
		{
			bool result = false;

			size_t pos = packet.find("Transfer-Encoding");
			if (std::string::npos != pos)
			{
				size_t crlf_pos = packet.find("\r\n");
				std::string val = packet.substr(pos, crlf_pos - pos);

				result = std::string::npos != val.find("chunked", 0);
			}

			return result;
		}

		static int ToInt(char* data, unsigned short len)
		{
			unsigned int result = 0;
			char* end;
			std::string buffer(data, len);

			//buffer = data.substr(0, len);
		
			return strtol(buffer.c_str(), &end, 16);
		}

	protected:
		static std::string MakeHeader(std::string method
									, std::string host
									, std::string path
									, unsigned short port
									, std::vector<std::string> headers
									, unsigned int datalen)
		{
			std::vector<std::string> src;

			src.push_back(method + " " + path + " HTTP/1.1");
			src.push_back("Host: " + host + ":" + to_string(port));
			src.push_back("Content-Type: application/json");
			src.push_back("Content-Length: " + to_string(datalen));
			src.push_back("Accept: */*");
			//src.push_back("Accept-Encoding: gzip, deflate, br");
			src.push_back("Connection: keep-alive");

			MergeHeader(src, headers);

			std::string buffer("");
			std::string result("");
			for (std::vector<std::string>::iterator it = src.begin(); it != src.end(); ++it)
			{
				buffer = (*it);
				if (buffer[buffer.length() - 1] == '\0')
				{
					buffer.resize(buffer.size() - 1);
				}
				
				result.append(buffer.c_str(), buffer.length());
				result.append("\r\n");
			}
			result.append("\r\n");

			return result;
		}

		static bool Request(
						std::string method,
						std::string host,
						std::string path,
						unsigned short port,
						std::vector<std::string> headers,
						std::string params,
						std::string& response,
						unsigned int timeout = 5000)
		{
			SOCKET	sock;
			WSADATA wsa;

			response.clear();

			if (0 != WSAStartup(MAKEWORD(2, 2), &wsa))
			{
				throw std::exception("WSAStartup failed.");
			}

			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (INVALID_SOCKET == sock)
			{
				throw std::exception("Failed to create socket instance.");
			}

			struct addrinfo*	addr_result;
			struct addrinfo		addr_hints;

			memset(&addr_hints, 0x00, sizeof(addr_hints));
			addr_hints.ai_family = AF_INET;
			addr_hints.ai_socktype = SOCK_STREAM;
			addr_hints.ai_protocol = IPPROTO_TCP;
			addr_hints.ai_flags = 0;

			int ret = getaddrinfo(host.c_str(), 0, &addr_hints, &addr_result);
			if (0 != ret)
			{
				printf("getaddrinfo failed.");
				return false;
			}

			sockaddr_in		sock_addr = { 0 };
			sock_addr.sin_family = AF_INET;
			sock_addr.sin_port = htons(port);
			sock_addr.sin_addr.S_un.S_addr = (ULONG)((sockaddr_in*)&addr_result->ai_addr[0])->sin_addr.S_un.S_addr;
			freeaddrinfo(addr_result);

			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

			ret = connect(sock, (sockaddr*)&sock_addr, sizeof(sock_addr));
			if (SOCKET_ERROR != ret)
			{
				std::string http_request;

				http_request = MakeHeader(method, host, path, port, headers, (int)params.length());
				http_request += params;

				ret = send(sock, http_request.c_str(), (int)http_request.size(), 0);
				if (SOCKET_ERROR != ret)
				{
					int			recvlen = 0;
					char		buffer[8192];
					bool		stop	= false;
					bool		chunked = false;
					std::string received;
					std::string body;

					while (!stop)
					{
						Sleep(10);

						memset(buffer, 0x00, sizeof(buffer) / sizeof(buffer[0]));

						recvlen = recv(sock, buffer, 8192, 0);
						received = std::string(buffer);

						if (recvlen == 0)
							break;

						if (recvlen == -1)
							break;

						if (!chunked && response.length() == 0)
						{
							chunked = IsChunked(received);
							if (chunked)
							{
								size_t pos = received.find("\r\n\r\n", 0);
								if (std::string::npos != pos)
								{
									size_t end_pos;
									size_t dat_pos;

									pos += 4;
									while (std::string::npos != (end_pos = received.find("\r\n", pos)))
									{
										dat_pos = end_pos + 2;

										int chunk_size = ToInt(&received[pos], end_pos - pos);
										if (chunk_size <= 0)
										{
											stop = true;
											break;
										}

										response.append(received.substr(dat_pos, chunk_size));
										pos = dat_pos + chunk_size + 2;
									}
								}
							}
							else
							{
								size_t pos = received.find("\r\n\r\n", 0);
								if (std::string::npos != pos)
								{
									pos += 4;
									size_t data_size = received.size() - pos;
									response.append(received.substr(pos, data_size));
								}
							}
						}
						else
						{
							if (chunked)
							{
								size_t pos = 0;
								size_t end_pos;
								size_t dat_pos;

								std::string chunk_buffer;

								while (std::string::npos != (end_pos = received.find("\r\n", pos)))
								{
									dat_pos = end_pos + 2;

									int chunk_size = ToInt(&received[pos], end_pos - pos);
									if (chunk_size <= 0)
									{
										stop = true;
										break;
									}

									response.append(received.substr(dat_pos, chunk_size));
									pos = dat_pos + chunk_size + 2;
								}
							}
							else
							{
								response.append(received);
							}
						}
					}
				}
			}

			closesocket(sock);
			sock = NULL;

			WSACleanup();

			return SOCKET_ERROR != ret;
		}

	public:
		static std::string to_string(int number)
		{
			std::ostringstream oss;
			oss << number;

			return oss.str();
		}

	public:
		static bool RequestGet(
						std::string host,
						std::string path,
						unsigned short port,
						std::vector<std::string> headers,
						std::string params,
						std::string& response,
						unsigned int timeout = 5000)
		{
			std::string method("GET");
			path += "?";
			path += params;
			return Request(method, host, path, port, headers, "", response, timeout);
		}

		static bool RequestPost(
						std::string host,
						std::string path,
						unsigned short port,
						std::vector<std::string> headers,
						std::string params,
						std::string& response,
						unsigned int timeout = 5000)
		{
			std::string method("POST");
			return Request(method, host, path, port, headers, params, response, timeout);
		}

		static bool RequestPut(
						std::string host,
						std::string path,
						unsigned short port,
						std::vector<std::string> headers,
						std::string params,
						std::string& response,
						unsigned int timeout = 5000)
		{
			std::string method("PUT");
			return Request(method, host, path, port, headers, params, response, timeout);
		}

		static bool RequestDelete(
						std::string host,
						std::string path,
						unsigned short port,
						std::vector<std::string> headers,
						std::string params,
						std::string& response,
						unsigned int timeout = 5000)
		{
			std::string method("DELETE");
			return Request(method, host, path, port, headers, params, response, timeout);
		}
	};
};