#include <iostream>
#include <fstream>
#include <string>
#include <cryptlib.h>
#include <hex.h>
#include <sha.h>
#include <files.h>  // Для работы с FileSource

using namespace CryptoPP;

void hashFile(const std::string& filename) {
    try {
        // Создаем объект для обработки файла
        SHA256 hash;
        std::string digest;

        FileSource fileSource(filename.c_str(), true,
                              new HashFilter(hash, new HexEncoder(new StringSink(digest))));

        std::cout << "Hash (SHA-256) of " << filename << ": " << digest << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
        return 1;
    }

    hashFile(argv[1]);
    return 0;
}
