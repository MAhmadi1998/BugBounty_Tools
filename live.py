import subprocess
import argparse

def LiveFinder(list):
    subprocess.run(f"cat {list} | httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect -H \"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0\" -H \"Referer: https://\$input\" -threads 1 -o lives.domain.brute.txt", shell=True, check=True)

def main():
    parser = argparse.ArgumentParser(description="Finding Live URLs.")
    parser.add_argument('-l', '--list', help='list of domains')

    args = parser.parse_args()

    if args.list:
        list = args.list
        LiveFinder(list)
        
        
    else:
        print("Please provide a list od domains using the '-l' or '--list' switch.")

if __name__ == "__main__":
    main()