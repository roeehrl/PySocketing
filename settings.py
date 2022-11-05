#helper functions.

PORT_INFO = "port.info"

def get_port():
    """returns the port configured in PORT_INFO file. if none is configured then return 1234"""
    try:
        with open(PORT_INFO) as file:
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

