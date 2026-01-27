import psutil

def main():
    for p in psutil.process_iter(['pid','ppid','name']):
        print(p.info)
        # break


if __name__ == "__main__":
    main()
