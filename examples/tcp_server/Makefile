# Makefile

CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto

TARGET = tcp_server
SOURCE = tcp_server.c

all: install_openssl $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)
	
install_openssl:
	@echo "Installing OpenSSL..."
	@sudo apt-get install -y libssl-dev
	@echo "OpenSSL installed successfully."
