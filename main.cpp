#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <iostream>
#include <thread>
#include <fstream>
#include <stdexcept>
#include <chrono>

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <vector>
#include <unordered_map>
#include <set>

volatile bool interrupted = false;

void handler(int s) {
    interrupted = true;
}

std::string ip2a(uint32_t ip) {
    unsigned char octet[4];
    char buf[16];

    octet[3] = ip & 0xff;
    octet[2] = (ip >> 8 ) & 0xff;
    octet[1] = (ip >> 16) & 0xff;
    octet[0] = (ip >> 24) & 0xff;

    sprintf(buf, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);

    return buf;
}

struct range {
    uint32_t lo, hi;

    range(const std::string &s) {
        uint32_t ol[4], oh[4];
        int ret = sscanf(s.c_str(), "%u.%u.%u.%u - %u.%u.%u.%u",
                ol, ol + 1, ol + 2, ol + 3,
                oh, oh + 1, oh + 2, oh + 3);
        if (ret == 8) {
            lo = (ol[0] << 24) | (ol[1] << 16) | (ol[2] << 8) | ol[3];
            hi = (oh[0] << 24) | (oh[1] << 16) | (oh[2] << 8) | oh[3];
            return;
        }
        int masklen;
        ret = sscanf(s.c_str(), "%u.%u.%u.%u/%u",
                ol, ol + 1, ol + 2, ol + 3, &masklen);
        if (ret == 5) {
            uint32_t ip = (ol[0] << 24) | (ol[1] << 16) | (ol[2] << 8) | ol[3];
            uint32_t mask = ~((1 << (32 - masklen)) - 1);
            lo = ip & mask;
            hi = lo + (~mask);
            return;
        }
        throw std::invalid_argument("Could not parse range `" + s + "'");
    }

    range(uint32_t lo, uint32_t hi) : lo(lo), hi(hi) { }
};

std::ostream &operator<<(std::ostream &o, const range &r) {
    return o << ip2a(r.lo) << " - " << ip2a(r.hi);
}

namespace std {

template<>
struct hash<range> {
    size_t operator()(const range &r) const {
        return hash<uint32_t>()(r.lo);
    }
};

template<>
struct equal_to<range> {
    bool operator()(const range &a, const range &b) const {
        return a.lo == b.lo;
    }
};

template<>
struct less<range> {
    bool operator()(const range &a, const range &b) {
        return a.lo < b.lo;
    }
};

}

struct ranges;
std::ostream &operator<<(std::ostream &o, const ranges &rr);

struct ranges {
    std::set<range> v;
    void insert(const range &r) {
        range nr(r);
        auto p = v.insert(r).first;
        auto pl(p), pr(p);
        bool kill_left = false, kill_right = false;
        if (p != v.begin()) {
            pl--;
            if (pl->hi + 1 == r.lo) {
                kill_left = true;
                nr.lo = pl->lo;
            }
        }
        pr++;
        if (pr != v.end()) {
            if (pr->lo == r.hi + 1) {
                kill_right = true;
                nr.hi = pr->hi;
            }
        }
/*
        std::cout << "rs = " << *this << std::endl;
        std::cout << "r  = " << r << ", kl = " << kill_left << ", kr = " << kill_right << std::endl;
        std::cout << "nr = " << nr << std::endl;
*/
        if (!kill_left && !kill_right)
            return;
        if (kill_left && !kill_right) {
            p++;
            v.erase(pl, p);
            v.insert(nr);
            return;
        }
        if (kill_right && !kill_left) {
            pr++;
            v.erase(p, pr);
            v.insert(nr);
            return;
        }
        pr++;
        v.erase(pl, pr);
        v.insert(nr);
    }
};

std::ostream &operator<<(std::ostream &o, const ranges &rr) {
    o << "[";
    for (const auto &x : rr.v)
        o << x << ";\n ";
    return o << "]";
}

struct scanner {
    std::unordered_map<range, uint32_t> gw;
    std::unordered_map<uint32_t, ranges> table;

    scanner(const std::string &fn) {
        std::fstream f(fn, std::ios::in);
        if (!f)
            throw std::invalid_argument("Cannot open " + fn);
        std::string line;
        while (std::getline(f, line)) {
            if (line.size() == 0 || line[0] == '#')
                continue;

            int gran = 0;
            auto split = line.find('@');
            if (split == std::string::npos)
                split = line.size();
            else
                gran = atoi(line.c_str() + split + 1);
            line.resize(split);
            range r(line);
            std::cout << "[" << r << "]" << "@" << gran << std::endl;

            uint64_t scansz = 1ul << (32 - gran);
            uint64_t top = r.hi;
            for (uint64_t i = r.lo; i <= top; i += scansz) {
                range sr(i, std::min<uint64_t>(i + scansz - 1, top));
                gw[sr] = 0;
            }
        }
    }

    void record(uint32_t ip, uint32_t gate) {
        gw[range(ip, ip)] = gate;
    }

    void process() {
        for (const auto ipr : gw) {
            uint32_t gwip = ipr.second;
            table[gwip].insert(ipr.first);
        }
        for (const auto &z : table) {
            std::cout << z.second << " -> " << ip2a(z.first) << std::endl;
        }
        std::fstream f("route.cfg", std::ios::out);
        for (const auto &z : table) {
            for (const auto &ip : z.second.v)
                f << ip << " -> " << ip2a(z.first) << std::endl;
        }
    }
};

struct net {
    int sock;
    volatile bool done;
    std::function<void (uint32_t, uint32_t)> ongw;

    void subscribe(std::function<void (uint32_t, uint32_t)> f) {
        ongw = f;
    }

    net() : done(false) {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            perror("socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)");
            throw;
        }
        sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(0);
        saddr.sin_addr.s_addr = htonl(0);
        if (bind(sock, reinterpret_cast<const sockaddr *>(&saddr), sizeof(saddr)) < 0) {
            perror("bind");
            throw;
        }
        int val, ret;
        val = IP_PMTUDISC_DONT;
        ret = setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &val, sizeof(val));
        if (ret < 0) {
            perror("setsockopt(IP_MTU_DISCOVER, IP_PMTUDISC_DONT)");
            throw;
        }
        val = 1;
        ret = setsockopt(sock, SOL_IP, IP_RECVTTL, &val, sizeof(val));
        if (ret < 0) {
            perror("setsockopt(IP_RECVTTL, 1)");
            throw;
        }
        val = 3;
        ret = setsockopt(sock, SOL_IP, IP_TTL, &val, sizeof(val));
        if (ret < 0) {
            perror("setsockopt(IP_TTL, 3)");
            throw;
        }
        val = 1;
        ret = setsockopt(sock, SOL_IP, IP_RECVERR, &val, sizeof(val));
        if (ret < 0) {
            perror("setsockopt(IP_RECVERR, 3)");
            throw;
        }
    }

    void stop() {
        usleep(100000);
        done = true;
    }

    void listen(
            ) {
        pollfd fds;
        fds.fd = sock;

        while (!done) {
            fds.events = POLLERR | POLLIN;

            int ms = 10; // 10 ms
            int ret = poll(&fds, 1, ms);
            if (ret <= 0)
                continue;
            if (!(fds.revents & POLLERR))
                continue;

            char buffer[1024];
            sockaddr_in remote;
            msghdr resp;
            iovec iov;
            icmphdr icmph;
            cmsghdr *cmsg;

            iov.iov_base = &icmph;
            iov.iov_len = sizeof(icmph);
            resp.msg_name = &remote;
            resp.msg_namelen = sizeof(remote);
            resp.msg_iov = &iov;
            resp.msg_iovlen = 1;
            resp.msg_flags = 0;
            resp.msg_control = buffer;
            resp.msg_controllen = sizeof(buffer);

            ret = recvmsg(sock, &resp, MSG_ERRQUEUE);
            if (ret < 0)
                continue;
            for (cmsg = CMSG_FIRSTHDR(&resp); cmsg; cmsg = CMSG_NXTHDR(&resp, cmsg)) {
                if (cmsg->cmsg_level != SOL_IP)
                    continue;
                if (cmsg->cmsg_type != IP_RECVERR)
                    continue;
                sock_extended_err *sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
                if (!sock_err)
                    continue;
                if (sock_err->ee_origin != SO_EE_ORIGIN_ICMP)
                    continue;
                if (sock_err->ee_type != ICMP_TIME_EXCEEDED)
                    continue;

                uint32_t ip = htonl(remote.sin_addr.s_addr);
                uint32_t gw = htonl(reinterpret_cast<sockaddr_in *>(SO_EE_OFFENDER(sock_err))->sin_addr.s_addr);

                ongw(ip, gw);
            }
        }
    }

    void probe(uint32_t ip) {
        sockaddr_in raddr;
        raddr.sin_family = AF_INET;
        raddr.sin_port = htons(34567);
        raddr.sin_addr.s_addr = htonl(ip);

        char msg[16] = {'R','O','U','T','E','S','C','A','N','N','E','R','v','1','.','0'};
        for (int retry = 0; retry < 3; retry++) {
            usleep(5000);
            int ret = sendto(sock, msg, sizeof(msg), 0,
                    reinterpret_cast<const sockaddr *>(&raddr), sizeof(raddr));
            if (ret < 0 && errno != EINVAL) {
                std::cout << std::endl;
                std::cerr << ip2a(ip);
                std::cerr.flush();
                perror(" sendto");
            }
        }
    }
};

void draw_progress(int tics, int maxtics) {
    std::cout << "\r";
    int i = 0;
    while (i++ < tics)
        std::cout << "*";
    while (i++ < maxtics)
        std::cout << ".";
}

int main() {
    struct sigaction sigint;
    sigint.sa_handler = handler;
    sigemptyset(&sigint.sa_mask);
    sigint.sa_flags = 0;
    sigaction(SIGINT, &sigint, NULL);

    scanner s("scan.txt");
    net n;

    n.subscribe([&s](uint32_t ip, uint32_t gw) { s.record(ip, gw); });

    std::thread listener([&n]() { n.listen(); });

    std::vector<uint32_t> ips;
    for (const auto &x : s.gw)
        ips.push_back(x.first.lo);
    std::sort(ips.begin(), ips.end());

    size_t i = 0;
    size_t nextout = 0;
    size_t step = 100;
    size_t ntics = 50;

    size_t nprobes = ips.size();

    std::cout << "Scanning " << nprobes << " IP addresses" << std::endl;

    const auto start = std::chrono::system_clock::now();

    for (uint32_t ip : ips) {
        if (i > nextout) {
            const auto now = std::chrono::system_clock::now();
            draw_progress(i * ntics / nprobes, ntics);
            double done = 1.0f * i / nprobes;
            std::chrono::duration<double> diff = now - start;
            diff *= (1 - done) / done;
            int secs = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
            int mins = secs / 60;
            secs -= 60 * mins;
            int hrs = mins / 60;
            mins -= 60 * hrs;
            std::cout << " ";
            std::cout.width(16);
            std::cout << std::left << ip2a(ip) << " ETC " << hrs << ":";
            std::cout.width(2);
            std::cout << mins << ":";
            std::cout.width(2);
            std::cout << secs;
            std::cout.flush();
            nextout += step;
        }
        i++;

        n.probe(ip);

        if (interrupted)
            break;
    }

    std::cout.flush();
    std::cout << "\nFinalizing..." << std::endl;

    n.stop();
    listener.join();

    s.process();

    return 0;
}
