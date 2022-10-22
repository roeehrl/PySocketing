
def get_port():
    try:
        with open("port.info") as file:
            content  = file.read()
            ports = content.splitlines()
            port = ports[0]
            return port

    except FileNotFoundError:
        print("no port config file found, defaulting to port 1234")
        return "1234"
    
    except:
        print("cofig file currupt, defaulting to port 1234")
        return "1234"

print(get_port())