#include <algorithm>
#include <cstddef>
#include <iterator>
#include <vector>

void merge(std::vector<int>& arr, std::size_t left, std::size_t mid, std::size_t right) {
    std::vector<int> tmp(right - left);
    std::size_t      i = left;
    std::size_t      j = mid;
    std::size_t      k = 0;

    while (i < mid && j < right) {
        if (arr[i] <= arr[j]) {
            tmp[k++] = arr[i++];
        } else {
            tmp[k++] = arr[j++];
        }
    }

    if (i < mid) {
        std::copy(arr.begin() + i, arr.begin() + mid, tmp.begin() + k);
    } else {
        std::copy(arr.begin() + j, arr.begin() + right, tmp.begin() + k);
    }

    for (std::size_t p = 0; p < tmp.size(); ++p) {
        arr[left + p] = tmp[p];
    }
}

void mergeSort(std::vector<int>& arr, std::size_t left, std::size_t right) {
    if (right - left > 1) {
        int mid = left + (right - left) / 2;
        mergeSort(arr, left, mid);
        mergeSort(arr, mid, right);
        merge(arr, left, mid, right);
    }
}

#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input-file> <output-file>\n";
        return 1;
    }

    std::ifstream input(argv[1], std::ios::in);
    if (!input) {
        std::cerr << "Failed to open input file: " << argv[1] << '\n';
        return 1;
    }

    std::vector<int> arr;
    arr.reserve(10000000);
    std::copy(std::istream_iterator<int>(input), std::istream_iterator<int>(), std::back_inserter(arr));

    mergeSort(arr, 0, arr.size());

    std::ofstream output(argv[2], std::ios::out);
    if (!output) {
        std::cerr << "Failed to open output file: " << argv[2] << '\n';
        return 1;
    }
    std::copy(arr.begin(), arr.end(), std::ostream_iterator<int>(output, "\n"));

    return 0;
}
