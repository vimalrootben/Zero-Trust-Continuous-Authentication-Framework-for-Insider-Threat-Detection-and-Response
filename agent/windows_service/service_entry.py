import sys
import logging
from agent.windows_service.service_wrapper import ZeroTrustEDRService

logging.basicConfig(level=logging.INFO)

def main():
    service = ZeroTrustEDRService()
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        print("Service installed successfully.")
    elif len(sys.argv) > 1 and sys.argv[1] == "--start":
        service.run()
    else:
        print("Usage: python -m agent.windows_service.service_entry [--install|--start|--stop]")

if __name__ == "__main__":
    main()
