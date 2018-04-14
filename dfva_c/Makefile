LIBS = -lconfig++ -lcurl -ljsoncpp -lcrypto -lcryptopp
CFLAGS = -O -Wall -c  $(LIBS)
CC = g++ 

client.o: client.cpp
	$(CC) $(CFLAGS) -c client.cpp

settingsmanager.o: settingsmanager.cpp
	$(CC) $(CFLAGS) -c settingsmanager.cpp

crypto.o: crypto.cpp
	$(CC) $(CFLAGS) -c crypto.cpp

clean: 
	rm -f dfva *.o 

dfva: settingsmanager.o client.o main.cpp crypto.o
	$(CC) -o dfva  main.cpp settingsmanager.o client.o crypto.o -I.  $(LIBS)
  
run:
	./dfva

all:
	dfva
