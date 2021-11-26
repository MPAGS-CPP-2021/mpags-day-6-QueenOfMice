#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "ProcessCommandLine.hpp"
#include "TransformChar.hpp"

#include <cctype>
#include <future>
#include <thread>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[])
{
    // Convert the command-line arguments into a more easily usable form
    const std::vector<std::string> cmdLineArgs{argv, argv + argc};

    // Options that might be set by the command-line arguments
    ProgramSettings settings{
        false, false, "", "", "", CipherMode::Encrypt, CipherType::Caesar};

    // Process command line arguments
    const bool cmdLineStatus{processCommandLine(cmdLineArgs, settings)};

    // Any failure in the argument processing means we can't continue
    // Use a non-zero return value to indicate failure
    if (!cmdLineStatus) {
        return 1;
    }

    // Handle help, if requested
    if (settings.helpRequested) {
        // Line splitting for readability
        std::cout
            << "Usage: mpags-cipher [-h/--help] [--version] [-i <file>] [-o <file>] [-c <cipher>] [-k <key>] [--encrypt/--decrypt]\n\n"
            << "Encrypts/Decrypts input alphanumeric text using classical ciphers\n\n"
            << "Available options:\n\n"
            << "  -h|--help        Print this help message and exit\n\n"
            << "  --version        Print version information\n\n"
            << "  -i FILE          Read text to be processed from FILE\n"
            << "                   Stdin will be used if not supplied\n\n"
            << "  -o FILE          Write processed text to FILE\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "  -c CIPHER        Specify the cipher to be used to perform the encryption/decryption\n"
            << "                   CIPHER can be caesar, playfair, or vigenere - caesar is the default\n\n"
            << "  -k KEY           Specify the cipher KEY\n"
            << "                   A null key, i.e. no encryption, is used if not supplied\n\n"
            << "  --encrypt        Will use the cipher to encrypt the input text (default behaviour)\n\n"
            << "  --decrypt        Will use the cipher to decrypt the input text\n\n"
            << std::endl;
        // Help requires no further action, so return from main
        // with 0 used to indicate success
        return 0;
    }

    // Handle version, if requested
    // Like help, requires no further action,
    // so return from main with zero to indicate success
    if (settings.versionRequested) {
        std::cout << "0.5.0" << std::endl;
        return 0;
    }

    // Initialise variables
    char inputChar{'x'};
    std::string inputText;

    // Read in user input from stdin/file
    if (!settings.inputFile.empty()) {
        // Open the file and check that we can read from it
        std::ifstream inputStream{settings.inputFile};
        if (!inputStream.good()) {
            std::cerr << "[error] failed to create istream on file '"
                      << settings.inputFile << "'" << std::endl;
            return 1;
        }

        // Loop over each character from the file
        while (inputStream >> inputChar) {
            inputText += transformChar(inputChar);
        }

    } else {
        // Loop over each character from user input
        // (until Return then CTRL-D (EOF) pressed)
        while (std::cin >> inputChar) {
            inputText += transformChar(inputChar);
        }
    }

    // Request construction of the appropriate cipher
    auto cipher = cipherFactory(settings.cipherType, settings.cipherKey);

    // Check that the cipher was constructed successfully
    if (!cipher) {
        std::cerr << "[error] problem constructing requested cipher"
                  << std::endl;
        return 1;
    }

    // create n chunks of the string outputText and apply the cipher in parallel 
    // to all of them...
    size_t j = 4; // hardcoded for now XXX later take from cmd line

    // vector containing futures of the threads
    std::vector< std::future< std::string > > futures;

    std::size_t substrLen = inputText.size()/j;

    for (std::size_t iThr = 0; iThr < j; iThr++) {
        std::string inTextChunk = "";
        if (iThr != j -1) {
            inTextChunk = inputText.substr(iThr*substrLen, substrLen);
        } else {
            inTextChunk = inputText.substr(iThr*substrLen, substrLen + inputText.size()%j);
        }

        // Lambda to start a thread that applies the cipher
        auto applyCiphOnThr = [&cipher, inTextChunk, &settings] () {
            std::cout << "[thread] Wait for it...\n"; 
            const std::string outTextChunk{cipher->applyCipher(inTextChunk, settings.cipherMode)};
            std::cout << "[thread] Done!\n";
            return outTextChunk;
        };

        futures.push_back(std::async(std::launch::async, applyCiphOnThr));
    }

    // wait until all threads are done, then put the chunks together
    bool wait = true;
    while (wait) {
        for (auto& f : futures) {
            // check for all threads if they are not(!) ready
            // and break as soon as one is not ready
            if (f.wait_for(std::chrono::seconds(1)) != std::future_status::ready) {
                break;
            } else {
                // else, all are ready --> good to go, set wait to false
                wait = false;
            }
        }
    }
    std::string outputText;
    for (auto& f : futures) {
        outputText += f.get();
    }

    // Run the cipher on the input text, specifying whether to encrypt/decrypt

    // Output the encrypted/decrypted text to stdout/file
    if (!settings.outputFile.empty()) {
        // Open the file and check that we can write to it
        std::ofstream outputStream{settings.outputFile};
        if (!outputStream.good()) {
            std::cerr << "[error] failed to create ostream on file '"
                      << settings.outputFile << "'" << std::endl;
            return 1;
        }

        // Print the encrypted/decrypted text to the file
        outputStream << outputText << std::endl;

    } else {
        // Print the encrypted/decrypted text to the screen
        std::cout << outputText << std::endl;
    }

    // No requirement to return from main, but we do so for clarity
    // and for consistency with other functions
    return 0;
}
