#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

void GenerateKeyAndIV(const std::string& password, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock hashedPassword(CryptoPP::SHA256::DIGESTSIZE);

    hash.CalculateDigest(hashedPassword, reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size());

    key.Assign(hashedPassword, CryptoPP::AES::DEFAULT_KEYLENGTH);

    iv.Assign(hashedPassword + CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
}

void EncryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
    try {
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
        GenerateKeyAndIV(password, key, iv);

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::FileSource(inputFilename.c_str(), true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::FileSink(outputFilename.c_str())
            )
        );

        std::cout << "Файл успешно зашифрован: " << outputFilename << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

void DecryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
    try {
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
        GenerateKeyAndIV(password, key, iv);

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        // Проверка на возможность дешифровки
        bool decryptionSuccess = false;
        try {
            CryptoPP::FileSource(inputFilename.c_str(), true,
                new CryptoPP::StreamTransformationFilter(decryptor,
                    new CryptoPP::FileSink(outputFilename.c_str())
                )
            );
            decryptionSuccess = true;
        } catch (const CryptoPP::Exception&) {
            // Неудачная попытка дешифровки — возможно неверный пароль
            std::cerr << "Ошибка: Неверный пароль или поврежденный файл." << std::endl;
        }

        if (!decryptionSuccess) {
            std::cerr << "Ошибка: Расшифровка не удалась. Возможно, пароль неверен." << std::endl;
        } else {
            std::cout << "Файл успешно расшифрован: " << outputFilename << std::endl;
        }

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Использование: " << argv[0] << " <encrypt/decrypt> <inputfile> <outputfile> <password>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFilename = argv[2];
    std::string outputFilename = argv[3];
    std::string password = argv[4];

    if (mode == "encrypt") {
        EncryptFile(inputFilename, outputFilename, password);
    } else if (mode == "decrypt") {
        DecryptFile(inputFilename, outputFilename, password);
    } else {
        std::cerr << "Неизвестный режим: " << mode << std::endl;
        return 1;
    }

    return 0;
}
