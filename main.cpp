#include "extractExample/extractExample.h"
#include "PIRExample/PIRExample.h"


int main() {
    // Extract an LWE ciphertext from RLWE ciphertext from index 3, whose value is 4
    extract_example(3, 4);
    // The first parameter is retrievaled index from database, begins from 0
    // and must be smaller than plaintext polynomial length
    // The second parameter is length of database
    PIRExample(5, 100);
    return 0;
}