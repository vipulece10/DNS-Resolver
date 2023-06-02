import datetime
import sys
import time

import dns.resolver

# iteratively query the servers to get next level servers
def getNextServers(query_servers, domain, type):
    result_servers = []
    for server in query_servers:
        # Query the Server with domainType as parameter to obtain subdomain servers
        domain_query = dns.message.make_query(domain, type)
        query_response = dns.query.udp(domain_query, server, timeout=1)
        if not query_response:
            return None

        answer_section = query_response.answer
        additional_section = query_response.additional
        authority_section = query_response.authority
        # if response has answer section,return the current server
        if answer_section:
            return [server]
        # if response has authority section,return the current server
        if authority_section and (authority_section[0].rdtype == dns.rdatatype.SOA):
            return [server]
        # if response has additional section,return the list of servers
        if additional_section:
            for fields in additional_section:
                result_servers.append(fields[0].to_text())
            if result_servers:
                return result_servers
        # if response has authority section with dns.rdatatype is not SOA ,resolve the name server again
        if authority_section:
            if authority_section[0][0].to_text():
                domain_dns_unresolved = dns.name.from_text(authority_section[0][0].to_text())
                domain_dns_tokens_unresolved = str(domain_dns_unresolved).split('.')
                dns_tokens_unresolved = list(reversed(domain_dns_tokens_unresolved[:-1]))
                return resolve(dns_tokens_unresolved, type)


def resolve(tokens, type):
    # list of root_servers
    servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
               '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
               '202.12.27.33']
    query = ""
    i = 0
    subdomain_servers = []
    # iterate over the subdomains down the hierarchy to resolve the domain
    while i < len(tokens):
        query = tokens[i] + '.' + query
        if i == 0:
            # to query the root servers for subdomain servers
            subdomain_servers = getNextServers(servers, query, type)
            if not subdomain_servers:
                return []
        else:
            if subdomain_servers:
                temp_servers = getNextServers(subdomain_servers, query, type)
                subdomain_servers = temp_servers
            else:
                break
        i = i + 1
    return subdomain_servers



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    isProcessResult = False
    domain_name = sys.argv[1]
    type = sys.argv[2]
    execution_start_time = time.time() * 1000
    size = 0
    domain_dns = dns.name.from_text(domain_name)
    domain_dns_tokens = str(domain_dns).split('.')
    dns_tokens = list(reversed(domain_dns_tokens[:-1]))
    resolved_servers = resolve(dns_tokens, type)
    for server in resolved_servers:
        # to get the IPv4 Address from the authoritative name server
        query = dns.message.make_query(domain_name, type)
        response = dns.query.udp(query, server, timeout=1)
        if response:
            isProcessResult = True
            break

    if isProcessResult:
        size += sys.getsizeof(response)
        if response.answer:
            # to get response for canonical name server
            if response.answer[0][0].rdtype == dns.rdatatype.CNAME:
                cname_domain_name = response.answer[0][0]
                cname_domain_dns = dns.name.from_text(str(cname_domain_name))
                cname_domain_dns_tokens = str(cname_domain_dns).split('.')
                cname_dns_tokens = list(reversed(cname_domain_dns_tokens[:-1]))
                cname_nameserver = resolve(cname_dns_tokens, type)

                for server in cname_nameserver:
                    resolve_type = 'A'
                    query = dns.message.make_query(cname_domain_dns, resolve_type)
                    server_response = dns.query.udp(query, server, timeout=1)
                    size += sys.getsizeof(server_response)
                    response.answer += server_response.answer

        execution_end_time = time.time() * 1000
        question_string = response.question[0].to_text() + '\n'
        answer_string = ""
        for answer in response.answer:
            answer_string += answer.to_text() + '\n'
        # print the output in the given format
        print('QUESTION SECTION:')
        print(question_string)
        print('ANSWER SECTION:')
        print(answer_string + '\n')

        print('Query time', str(execution_end_time - execution_start_time) + ' msec')
        print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
        print('MSG SIZE rcvd:', size)
    else:
        execution_end_time = time.time() * 1000
        print('Not able to resolve domain')


