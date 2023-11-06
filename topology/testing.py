import topology


def ping(client, server, expected, count=1, wait=1):

    # TODO: What if ping fails? How long does it take? Add a timeout to the command!
    cmd = f"ping {server} -c {count} -w {wait} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd)
    ret = ret.strip()
    ret = ret[-1]
    # TODO: Here you should compare the return value "ret" with the expected value
    # (consider both failures
    
    if (int(ret) == 0 and expected ) or (int(ret) != 0 and not(expected) ):
        return True
    else:
        return False
   # True means "everything went as expected"


def curl(client, server, method = "GET" , payload= None,file = None, port=80, expected=True):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server

        # TODO: Specify HTTP method
        # TODO: Pass some payload (a.k.a. data). You may have to add some escaped quotes!
        # The magic string at the end reditect everything to the black hole and just print the return code
        if payload:
            cmd = f"curl --connect-timeout 3 --max-time 3 -s -X {method}  -d '{payload}' {server}:{port} > /dev/null 2>&1; echo $?"
        else:
            cmd = f"curl --connect-timeout 3 --max-time 3 -s {server}:{port} > /dev/null 2>&1; echo $?"
        ret = client.cmd(cmd).strip()
        if (int(ret) == 0 and expected == True) or (int(ret) != 0 and expected == False):
            return True
        else:
            return False

        # TODO: What value do you expect?  # True means "everyhing went as expected"
