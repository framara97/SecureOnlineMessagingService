CC=g++

basic: SecureChatClient.cpp SecureChatServer.cpp Utility.cpp User.cpp client_main.cpp server_main.cpp
	$(CC) -c SecureChatClient.cpp SecureChatServer.cpp User.cpp Utility.cpp client_main.cpp server_main.cpp
	$(CC) -pthread -o client_main client_main.o SecureChatClient.o User.o Utility.o -lcrypto
	$(CC) -pthread -o server_main server_main.o SecureChatServer.o User.o Utility.o -lcrypto

client_main: SecureChatClient.cpp server_main.cpp Utility.cpp user.cpp
	$(CC) -c SecureChatClient.cpp User.cpp Utility.cpp client_main.cpp
	$(CC) -pthread -o client_main SecureChatClient.o User.o Utility.o client_main.o -lcrypto

server_main: SecureChatServer.cpp Utility.cpp User.cpp server_main.cpp
	$(CC) -c SecureChatServer.cpp User.cpp Utility.cpp server_main.cpp
	$(CC) -pthread -o server_main SecureChatServer.o User.o Utility.o server_main.o -lcrypto

clean:
	rm *.o
