import datetime
import sys
import time
import dns.dnssec
import dns.resolver

#root servers DS record  taken  from http://data.iana.org/root-anchors/root-anchors.xml
root_dslist = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5', '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']

#method to validate RRset received from parent zone and to validate KSK
def validateZSKandKSK(domain_name, hashed_key, dsRecordList, rrSig, rrSet):
    originDict = {dns.name.from_text(domain_name): rrSet}
    flag_ZSK = True
    flag_KSK = False

    #to validate RRSet record using RRSig
    try:
        dns.dnssec.validate(rrSet, rrSig, originDict)
    except dns.dnssec.ValidationFailure:
        flag_ZSK = False

    #to validate KSK recieved from Parent
    for entry in dsRecordList:
        if str(hashed_key) == str(entry):
            flag_KSK = True
            break
    #if any of the validations are unsuccessful return DNSSEC verificaton failed to the o/p
    if flag_ZSK and flag_KSK:
        return True
    else:
        print('DNSSEC Verification failed')
        return False

# iteratively query the servers to get next level servers
# if isFetchZSK flag is true return RRSig,RRset and ZSK from parent Zone
def getNextServers(query_servers, domain, isFetchZSK):
    result_servers = []
    dsrecordList = None
    dns_algo = None
    isSOA = False
    for server in query_servers:
        #Query the Server with DNSKEY as parameter to obtain DNS records
        domain_query = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        query_response = dns.query.tcp(domain_query, server, timeout=10)
        if not query_response:
            return None
        if isFetchZSK:
            RRSig = None
            RRSet = None
            ZSK = None
            out_parentloop = False

            if len(query_response.answer) > 0:
                #to obatin RRSig from the response
                for item in query_response.answer:
                    if (item.rdtype ==  dns.rdatatype.RRSIG):
                        RRSig = item
                        break
                #to obtain RRSet and ZSK from the response
                for item in query_response.answer:
                    if (item.rdtype == dns.rdatatype.DNSKEY):
                        for element in item:
                            if(element.flags == 257):
                                RRSet = item
                                ZSK = element
                                out_parentloop = True
                                break
                        if out_parentloop:
                            break
            return RRSig, RRSet, ZSK
        else:
            answer_section = query_response.answer
            additional_section = query_response.additional
            authority_section = query_response.authority
            # to obtain child's encryption algorithm and child ds record
            if authority_section:
                for items in authority_section:
                    if(items.rdtype == dns.rdatatype.DS):
                        dsrecordList = items[0]
                        if(items[0].digest_type == 1):
                            dns_algo = "sha1"
                        if(items[0].digest_type == 2):
                            dns_algo = "sha256"
                        break
            #if response has answer section,return the current server
            if answer_section:
                return [server], dsrecordList, dns_algo, isSOA
            #if response has authority section,return the current server and mark SOA flag as true
            if authority_section and (authority_section[0].rdtype == dns.rdatatype.SOA):
                isSOA = True
                return [server], dsrecordList, dns_algo, isSOA
            # if response has additional section,return the list of servers
            if additional_section:
                for fields in additional_section:
                    result_servers.append(fields[0].to_text())
                if result_servers:
                    return result_servers, dsrecordList, dns_algo, isSOA
            # if response has authority section with dns.rdatatype is not SOA ,resolve the name server again
            if authority_section:
                if authority_section[0][0].to_text():
                   domain_dns_unresolved = dns.name.from_text(authority_section[0][0].to_text())
                   domain_dns_tokens_unresolved = str(domain_dns_unresolved).split('.')
                   dns_tokens_unresolved = list(reversed(domain_dns_tokens_unresolved[:-1]))
                   return resolve(dns_tokens_unresolved), dsrecordList, dns_algo, isSOA




def resolve(tokens):
    # list of root_servers
    servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
               '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
               '202.12.27.33']
    query = ""
    i = 0
    subdomain_servers = []
    dsRecordList = None
    dns_algo = ""
    isSOA = False
    #iterate over the subdomains down the hierarchy to resolve the domain
    while i < len(tokens):
        rrSig = None
        rrSet = None
        ZSK = None
        previousQuery = query
        query = tokens[i] + '.' + query
        #to validation and query the root servers for subdomain servers
        if i == 0:
            for root_server in servers:
                rrSig, rrSet, ZSK = getNextServers([root_server], '.', True)
                if not rrSig and not rrSet and not ZSK:
                    continue
                hashed_key = dns.dnssec.make_ds('.', ZSK, 'sha256')
                isrootValidated = validateZSKandKSK('.', hashed_key, root_dslist, rrSig, rrSet)
                if isrootValidated:
                    subdomain_servers, dsRecordList, dns_algo, isSOA = getNextServers([root_server], query, False)
                    if subdomain_servers:
                        break

        else:
            #to validate and query the servers to get next level servers
            if subdomain_servers:
                for subdomain_server in subdomain_servers:
                    server_toquery=[]
                    server_toquery.append(subdomain_server)
                    rrSig, rrSet, ZSK = getNextServers(server_toquery, previousQuery, True)
                    if rrSig and rrSet and ZSK:
                        break

                if dsRecordList and dns_algo and rrSig and ZSK:
                    hashed_key = dns.dnssec.make_ds(previousQuery, ZSK, dns_algo)
                    isValidated = validateZSKandKSK(previousQuery, hashed_key, [dsRecordList], rrSig, rrSet)
                else:
                    print('DNSSec not enabled')
                    return None


                if isValidated:
                    temp_servers, dsRecordList, dns_algo, isSOA = getNextServers(subdomain_servers, query, False)
                    subdomain_servers = temp_servers
                    if isSOA:
                        break
                else:
                    return None
            else:
                break
        i = i + 1

    return subdomain_servers





if __name__ == '__main__':
    isProcessResult = False
    domain_name = sys.argv[1]
    execution_start_time = time.time() * 1000
    domain_dns = dns.name.from_text(domain_name)
    domain_dns_tokens = str(domain_dns).split('.')
    dns_tokens = list(reversed(domain_dns_tokens[:-1]))
    resolved_servers = resolve(dns_tokens)

    if resolved_servers:
        # to get the IPv4 Address from the authoritative name server
        for server in resolved_servers:
            query = dns.message.make_query(domain_name, "A", want_dnssec=False)
            response = dns.query.tcp(query, server, timeout=10)
            if response:
                isProcessResult = True
                break

        if isProcessResult:
            if response.answer:
                # to get response for canonical name server
                if response.answer[0][0].rdtype == dns.rdatatype.CNAME:
                    cname_domain_name = response.answer[0][0]
                    cname_domain_dns = dns.name.from_text(str(cname_domain_name))
                    cname_domain_dns_tokens = str(cname_domain_dns).split('.')
                    cname_dns_tokens = list(reversed(cname_domain_dns_tokens[:-1]))
                    cname_nameserver = resolve(cname_dns_tokens)

                    for server in cname_nameserver:
                        resolve_type = 'A'
                        query = dns.message.make_query(cname_domain_dns, resolve_type)
                        server_response = dns.query.udp(query, server, timeout=1)
                        response.answer += server_response.answer

            execution_end_time = time.time() * 1000
            question_string = response.question[0].to_text() + '\n'
            answer_string = ""
            for answer in response.answer:
                answer_string += answer.to_text()

            #print the output in the given format
            print('QUESTION SECTION:')
            print(question_string)
            print('ANSWER SECTION:')
            print(answer_string + '\n')

            print('Query time', str(execution_end_time - execution_start_time) + ' msec')
            print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
            print('MSG SIZE rcvd:', sys.getsizeof(response))
        else:
            execution_end_time = time.time() * 1000
            print('Not able to resolve domain')



