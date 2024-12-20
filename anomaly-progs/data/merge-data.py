#!/usr/bin/env python3

import random
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--size', type=int, default=10000000, help='Number of elements to generate')
    parser.add_argument('-o', '--output', type=str, default='data/merge-data.txt', help='Output file')
    parser.add_argument('-m', '--max', type=int, default=50000000, help='Maximum value of element')
    args = parser.parse_args()

    size = args.size
    output = args.output
    max = args.max
    with open(output, 'w') as f:
        N = size
        for i in range(N):
            f.write(f'{random.randint(0, max)}\n')

if __name__ == '__main__':
    main()
