#include "extractExample.hpp"


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Extract " << argv[1] << " from index " << "argv[0]" << std::endl;
    }
    std::size_t index = static_cast<std::size_t>(atoi(argv[1])); 
    std::size_t value = static_cast<std::size_t>(atoi(argv[2])); 
    std::size_t result = extract_example(index, value);
    std::cout << "Index: " << index << ", value: " << value << ", result: " << result << std::endl;
    return result;
}