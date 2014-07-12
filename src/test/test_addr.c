/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ADDRESSMAP_PRIVATE
#include "orconfig.h"
#include "or.h"
#include "test.h"
#include "addressmap.h"

static void
test_addr_basic(void)
{
  uint32_t u32;
  uint16_t u16;
  char *cp;

  /* Test addr_port_lookup */
  cp = NULL; u32 = 3; u16 = 3;
  test_assert(!addr_port_lookup(LOG_WARN, "1.2.3.4", &cp, &u32, &u16));
  test_streq(cp, "1.2.3.4");
  test_eq(u32, 0x01020304u);
  test_eq(u16, 0);
  tor_free(cp);
  test_assert(!addr_port_lookup(LOG_WARN, "4.3.2.1:99", &cp, &u32, &u16));
  test_streq(cp, "4.3.2.1");
  test_eq(u32, 0x04030201u);
  test_eq(u16, 99);
  tor_free(cp);
  test_assert(!addr_port_lookup(LOG_WARN, "nonexistent.address:4040",
                               &cp, NULL, &u16));
  test_streq(cp, "nonexistent.address");
  test_eq(u16, 4040);
  tor_free(cp);
  test_assert(!addr_port_lookup(LOG_WARN, "localhost:9999", &cp, &u32, &u16));
  test_streq(cp, "localhost");
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 9999);
  tor_free(cp);
  u32 = 3;
  test_assert(!addr_port_lookup(LOG_WARN, "localhost", NULL, &u32, &u16));
  test_eq_ptr(cp, NULL);
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 0);
  tor_free(cp);

  test_assert(addr_port_lookup(LOG_WARN, "localhost:3", &cp, &u32, NULL));
  tor_free(cp);

  test_eq(0, addr_mask_get_bits(0x0u));
  test_eq(32, addr_mask_get_bits(0xFFFFFFFFu));
  test_eq(16, addr_mask_get_bits(0xFFFF0000u));
  test_eq(31, addr_mask_get_bits(0xFFFFFFFEu));
  test_eq(1, addr_mask_get_bits(0x80000000u));

  /* Test inet_ntop */
  {
    char tmpbuf[TOR_ADDR_BUF_LEN];
    const char *ip = "176.192.208.224";
    struct in_addr in;

    /* good round trip */
    test_eq(tor_inet_pton(AF_INET, ip, &in), 1);
    test_eq_ptr(tor_inet_ntop(AF_INET, &in, tmpbuf, sizeof(tmpbuf)), &tmpbuf);
    test_streq(tmpbuf, ip);

    /* just enough buffer length */
    test_streq(tor_inet_ntop(AF_INET, &in, tmpbuf, strlen(ip) + 1), ip);

    /* too short buffer */
    test_eq_ptr(tor_inet_ntop(AF_INET, &in, tmpbuf, strlen(ip)), NULL);
  }

 done:
  ;
}

#define test_op_ip6_(a,op,b,e1,e2)                               \
  STMT_BEGIN                                                     \
  tt_assert_test_fmt_type(a,b,e1" "#op" "e2,struct in6_addr*,    \
    (memcmp(val1_->s6_addr, val2_->s6_addr, 16) op 0),           \
    char *, "%s",                                                \
    { int i; char *cp;                                           \
      cp = print_ = tor_malloc(64);                              \
      for (i=0;i<16;++i) {                                       \
        tor_snprintf(cp, 3,"%02x", (unsigned)value_->s6_addr[i]);\
        cp += 2;                                                 \
        if (i != 15) *cp++ = ':';                                \
      }                                                          \
    },                                                           \
    { tor_free(print_); },                                       \
    TT_EXIT_TEST_FUNCTION                                        \
  );                                                             \
  STMT_END

/** Helper: Assert that two strings both decode as IPv6 addresses with
 * tor_inet_pton(), and both decode to the same address. */
#define test_pton6_same(a,b) STMT_BEGIN                \
     test_eq(tor_inet_pton(AF_INET6, a, &a1), 1);      \
     test_eq(tor_inet_pton(AF_INET6, b, &a2), 1);      \
     test_op_ip6_(&a1,==,&a2,#a,#b);                   \
  STMT_END

/** Helper: Assert that <b>a</b> is recognized as a bad IPv6 address by
 * tor_inet_pton(). */
#define test_pton6_bad(a)                       \
  test_eq(0, tor_inet_pton(AF_INET6, a, &a1))

/** Helper: assert that <b>a</b>, when parsed by tor_inet_pton() and displayed
 * with tor_inet_ntop(), yields <b>b</b>. Also assert that <b>b</b> parses to
 * the same value as <b>a</b>. */
#define test_ntop6_reduces(a,b) STMT_BEGIN                              \
    test_eq(tor_inet_pton(AF_INET6, a, &a1), 1);                        \
    test_streq(tor_inet_ntop(AF_INET6, &a1, buf, sizeof(buf)), b);      \
    test_eq(tor_inet_pton(AF_INET6, b, &a2), 1);                        \
    test_op_ip6_(&a1, ==, &a2, a, b);                                   \
  STMT_END

/** Helper: assert that <b>a</b> parses by tor_inet_pton() into a address that
 * passes tor_addr_is_internal() with <b>for_listening</b>. */
#define test_internal_ip(a,for_listening) STMT_BEGIN           \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1); \
    t1.family = AF_INET6;                                      \
    if (!tor_addr_is_internal(&t1, for_listening))             \
      test_fail_msg( a "was not internal.");                   \
  STMT_END

/** Helper: assert that <b>a</b> parses by tor_inet_pton() into a address that
 * does not pass tor_addr_is_internal() with <b>for_listening</b>. */
#define test_external_ip(a,for_listening) STMT_BEGIN           \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1); \
    t1.family = AF_INET6;                                      \
    if (tor_addr_is_internal(&t1, for_listening))              \
      test_fail_msg(a  "was not external.");                   \
  STMT_END

/** Helper: Assert that <b>a</b> and <b>b</b>, when parsed by
 * tor_inet_pton(), give addresses that compare in the order defined by
 * <b>op</b> with tor_addr_compare(). */
#define test_addr_compare(a, op, b) STMT_BEGIN                    \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1);    \
    test_eq(tor_inet_pton(AF_INET6, b, &t2.addr.in6_addr), 1);    \
    t1.family = t2.family = AF_INET6;                             \
    r = tor_addr_compare(&t1,&t2,CMP_SEMANTIC);                   \
    if (!(r op 0))                                                \
      test_fail_msg("failed: tor_addr_compare("a","b") "#op" 0"); \
  STMT_END

/** Helper: Assert that <b>a</b> and <b>b</b>, when parsed by
 * tor_inet_pton(), give addresses that compare in the order defined by
 * <b>op</b> with tor_addr_compare_masked() with <b>m</b> masked. */
#define test_addr_compare_masked(a, op, b, m) STMT_BEGIN          \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1);    \
    test_eq(tor_inet_pton(AF_INET6, b, &t2.addr.in6_addr), 1);    \
    t1.family = t2.family = AF_INET6;                             \
    r = tor_addr_compare_masked(&t1,&t2,m,CMP_SEMANTIC);          \
    if (!(r op 0))                                                \
      test_fail_msg("failed: tor_addr_compare_masked("a","b","#m") "#op" 0"); \
  STMT_END

/** Helper: assert that <b>xx</b> is parseable as a masked IPv6 address with
 * ports by tor_parse_mask_addr_ports(), with family <b>f</b>, IP address
 * as 4 32-bit words <b>ip1...ip4</b>, mask bits as <b>mm</b>, and port range
 * as <b>pt1..pt2</b>. */
#define test_addr_mask_ports_parse(xx, f, ip1, ip2, ip3, ip4, mm, pt1, pt2) \
  STMT_BEGIN                                                                \
    test_eq(tor_addr_parse_mask_ports(xx, 0, &t1, &mask, &port1, &port2),   \
            f);                                                             \
    p1=tor_inet_ntop(AF_INET6, &t1.addr.in6_addr, bug, sizeof(bug));        \
    test_eq(htonl(ip1), tor_addr_to_in6_addr32(&t1)[0]);            \
    test_eq(htonl(ip2), tor_addr_to_in6_addr32(&t1)[1]);            \
    test_eq(htonl(ip3), tor_addr_to_in6_addr32(&t1)[2]);            \
    test_eq(htonl(ip4), tor_addr_to_in6_addr32(&t1)[3]);            \
    test_eq(mask, mm);                                     \
    test_eq(port1, pt1);                                   \
    test_eq(port2, pt2);                                   \
  STMT_END

/** Run unit tests for IPv6 encoding/decoding/manipulation functions. */
static void
test_addr_ip6_helpers(void)
{
  char buf[TOR_ADDR_BUF_LEN], bug[TOR_ADDR_BUF_LEN];
  char rbuf[REVERSE_LOOKUP_NAME_BUF_LEN];
  struct in6_addr a1, a2;
  tor_addr_t t1, t2;
  int r, i;
  uint16_t port1, port2;
  maskbits_t mask;
  const char *p1;
  struct sockaddr_storage sa_storage;
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  /* Test tor_inet_ntop and tor_inet_pton: IPv6 */
  {
    const char *ip = "2001::1234";
    const char *ip_ffff = "::ffff:192.168.1.2";

    /* good round trip */
    test_eq(tor_inet_pton(AF_INET6, ip, &a1), 1);
    test_eq_ptr(tor_inet_ntop(AF_INET6, &a1, buf, sizeof(buf)), &buf);
    test_streq(buf, ip);

    /* good round trip - ::ffff:0:0 style */
    test_eq(tor_inet_pton(AF_INET6, ip_ffff, &a2), 1);
    test_eq_ptr(tor_inet_ntop(AF_INET6, &a2, buf, sizeof(buf)), &buf);
    test_streq(buf, ip_ffff);

    /* just long enough buffer (remember \0) */
    test_streq(tor_inet_ntop(AF_INET6, &a1, buf, strlen(ip)+1), ip);
    test_streq(tor_inet_ntop(AF_INET6, &a2, buf, strlen(ip_ffff)+1),
               ip_ffff);

    /* too short buffer (remember \0) */
    test_eq_ptr(tor_inet_ntop(AF_INET6, &a1, buf, strlen(ip)), NULL);
    test_eq_ptr(tor_inet_ntop(AF_INET6, &a2, buf, strlen(ip_ffff)), NULL);
  }

  /* ==== Converting to and from sockaddr_t. */
  sin = (struct sockaddr_in *)&sa_storage;
  sin->sin_family = AF_INET;
  sin->sin_port = htons(9090);
  sin->sin_addr.s_addr = htonl(0x7f7f0102); /*127.127.1.2*/
  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin, &port1);
  test_eq(tor_addr_family(&t1), AF_INET);
  test_eq(tor_addr_to_ipv4h(&t1), 0x7f7f0102);
  tt_int_op(port1, ==, 9090);

  memset(&sa_storage, 0, sizeof(sa_storage));
  test_eq(sizeof(struct sockaddr_in),
          tor_addr_to_sockaddr(&t1, 1234, (struct sockaddr *)&sa_storage,
                               sizeof(sa_storage)));
  test_eq(1234, ntohs(sin->sin_port));
  test_eq(0x7f7f0102, ntohl(sin->sin_addr.s_addr));

  memset(&sa_storage, 0, sizeof(sa_storage));
  sin6 = (struct sockaddr_in6 *)&sa_storage;
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = htons(7070);
  sin6->sin6_addr.s6_addr[0] = 128;
  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin6, &port1);
  test_eq(tor_addr_family(&t1), AF_INET6);
  tt_int_op(port1, ==, 7070);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 0);
  test_streq(p1, "8000::");

  memset(&sa_storage, 0, sizeof(sa_storage));
  test_eq(sizeof(struct sockaddr_in6),
          tor_addr_to_sockaddr(&t1, 9999, (struct sockaddr *)&sa_storage,
                               sizeof(sa_storage)));
  test_eq(AF_INET6, sin6->sin6_family);
  test_eq(9999, ntohs(sin6->sin6_port));
  test_eq(0x80000000, ntohl(S6_ADDR32(sin6->sin6_addr)[0]));

  /* ==== tor_addr_lookup: static cases.  (Can't test dns without knowing we
   * have a good resolver. */
  test_eq(0, tor_addr_lookup("127.128.129.130", AF_UNSPEC, &t1));
  test_eq(AF_INET, tor_addr_family(&t1));
  test_eq(tor_addr_to_ipv4h(&t1), 0x7f808182);

  test_eq(0, tor_addr_lookup("9000::5", AF_UNSPEC, &t1));
  test_eq(AF_INET6, tor_addr_family(&t1));
  test_eq(0x90, tor_addr_to_in6_addr8(&t1)[0]);
  test_assert(tor_mem_is_zero((char*)tor_addr_to_in6_addr8(&t1)+1, 14));
  test_eq(0x05, tor_addr_to_in6_addr8(&t1)[15]);

  /* === Test pton: valid af_inet6 */
  /* Simple, valid parsing. */
  r = tor_inet_pton(AF_INET6,
                    "0102:0304:0506:0708:090A:0B0C:0D0E:0F10", &a1);
  test_assert(r==1);
  for (i=0;i<16;++i) { test_eq(i+1, (int)a1.s6_addr[i]); }
  /* ipv4 ending. */
  test_pton6_same("0102:0304:0506:0708:090A:0B0C:0D0E:0F10",
                  "0102:0304:0506:0708:090A:0B0C:13.14.15.16");
  /* shortened words. */
  test_pton6_same("0001:0099:BEEF:0000:0123:FFFF:0001:0001",
                  "1:99:BEEF:0:0123:FFFF:1:1");
  /* zeros at the beginning */
  test_pton6_same("0000:0000:0000:0000:0009:C0A8:0001:0001",
                  "::9:c0a8:1:1");
  test_pton6_same("0000:0000:0000:0000:0009:C0A8:0001:0001",
                  "::9:c0a8:0.1.0.1");
  /* zeros in the middle. */
  test_pton6_same("fe80:0000:0000:0000:0202:1111:0001:0001",
                  "fe80::202:1111:1:1");
  /* zeros at the end. */
  test_pton6_same("1000:0001:0000:0007:0000:0000:0000:0000",
                  "1000:1:0:7::");

  /* === Test ntop: af_inet6 */
  test_ntop6_reduces("0:0:0:0:0:0:0:0", "::");

  test_ntop6_reduces("0001:0099:BEEF:0006:0123:FFFF:0001:0001",
                     "1:99:beef:6:123:ffff:1:1");

  //test_ntop6_reduces("0:0:0:0:0:0:c0a8:0101", "::192.168.1.1");
  test_ntop6_reduces("0:0:0:0:0:ffff:c0a8:0101", "::ffff:192.168.1.1");
  test_ntop6_reduces("002:0:0000:0:3::4", "2::3:0:0:4");
  test_ntop6_reduces("0:0::1:0:3", "::1:0:3");
  test_ntop6_reduces("008:0::0", "8::");
  test_ntop6_reduces("0:0:0:0:0:ffff::1", "::ffff:0.0.0.1");
  test_ntop6_reduces("abcd:0:0:0:0:0:7f00::", "abcd::7f00:0");
  test_ntop6_reduces("0000:0000:0000:0000:0009:C0A8:0001:0001",
                     "::9:c0a8:1:1");
  test_ntop6_reduces("fe80:0000:0000:0000:0202:1111:0001:0001",
                     "fe80::202:1111:1:1");
  test_ntop6_reduces("1000:0001:0000:0007:0000:0000:0000:0000",
                     "1000:1:0:7::");

  /* Bad af param */
  test_eq(tor_inet_pton(AF_UNSPEC, 0, 0), -1);

  /* === Test pton: invalid in6. */
  test_pton6_bad("foobar.");
  test_pton6_bad("-1::");
  test_pton6_bad("00001::");
  test_pton6_bad("10000::");
  test_pton6_bad("::10000");
  test_pton6_bad("55555::");
  test_pton6_bad("9:-60::");
  test_pton6_bad("9:+60::");
  test_pton6_bad("9|60::");
  test_pton6_bad("0x60::");
  test_pton6_bad("::0x60");
  test_pton6_bad("9:0x60::");
  test_pton6_bad("1:2:33333:4:0002:3::");
  test_pton6_bad("1:2:3333:4:fish:3::");
  test_pton6_bad("1:2:3:4:5:6:7:8:9");
  test_pton6_bad("1:2:3:4:5:6:7");
  test_pton6_bad("1:2:3:4:5:6:1.2.3.4.5");
  test_pton6_bad("1:2:3:4:5:6:1.2.3");
  test_pton6_bad("::1.2.3");
  test_pton6_bad("::1.2.3.4.5");
  test_pton6_bad("::ffff:0xff.0.0.0");
  test_pton6_bad("::ffff:ff.0.0.0");
  test_pton6_bad("::ffff:256.0.0.0");
  test_pton6_bad("::ffff:-1.0.0.0");
  test_pton6_bad("99");
  test_pton6_bad("");
  test_pton6_bad(".");
  test_pton6_bad(":");
  test_pton6_bad("1::2::3:4");
  test_pton6_bad("a:::b:c");
  test_pton6_bad(":::a:b:c");
  test_pton6_bad("a:b:c:::");

  /* test internal checking */
  test_external_ip("fbff:ffff::2:7", 0);
  test_internal_ip("fc01::2:7", 0);
  test_internal_ip("fc01::02:7", 0);
  test_internal_ip("fc01::002:7", 0);
  test_internal_ip("fc01::0002:7", 0);
  test_internal_ip("fdff:ffff::f:f", 0);
  test_external_ip("fe00::3:f", 0);

  test_external_ip("fe7f:ffff::2:7", 0);
  test_internal_ip("fe80::2:7", 0);
  test_internal_ip("febf:ffff::f:f", 0);

  test_internal_ip("fec0::2:7:7", 0);
  test_internal_ip("feff:ffff::e:7:7", 0);
  test_external_ip("ff00::e:7:7", 0);

  test_internal_ip("::", 0);
  test_internal_ip("::1", 0);
  test_internal_ip("::1", 1);
  test_internal_ip("::", 0);
  test_external_ip("::", 1);
  test_external_ip("::2", 0);
  test_external_ip("2001::", 0);
  test_external_ip("ffff::", 0);

  test_external_ip("::ffff:0.0.0.0", 1);
  test_internal_ip("::ffff:0.0.0.0", 0);
  test_internal_ip("::ffff:0.255.255.255", 0);
  test_external_ip("::ffff:1.0.0.0", 0);

  test_external_ip("::ffff:9.255.255.255", 0);
  test_internal_ip("::ffff:10.0.0.0", 0);
  test_internal_ip("::ffff:10.255.255.255", 0);
  test_external_ip("::ffff:11.0.0.0", 0);

  test_external_ip("::ffff:126.255.255.255", 0);
  test_internal_ip("::ffff:127.0.0.0", 0);
  test_internal_ip("::ffff:127.255.255.255", 0);
  test_external_ip("::ffff:128.0.0.0", 0);

  test_external_ip("::ffff:172.15.255.255", 0);
  test_internal_ip("::ffff:172.16.0.0", 0);
  test_internal_ip("::ffff:172.31.255.255", 0);
  test_external_ip("::ffff:172.32.0.0", 0);

  test_external_ip("::ffff:192.167.255.255", 0);
  test_internal_ip("::ffff:192.168.0.0", 0);
  test_internal_ip("::ffff:192.168.255.255", 0);
  test_external_ip("::ffff:192.169.0.0", 0);

  test_external_ip("::ffff:169.253.255.255", 0);
  test_internal_ip("::ffff:169.254.0.0", 0);
  test_internal_ip("::ffff:169.254.255.255", 0);
  test_external_ip("::ffff:169.255.0.0", 0);
  test_assert(is_internal_IP(0x7f000001, 0));

  /* tor_addr_compare(tor_addr_t x2) */
  test_addr_compare("ffff::", ==, "ffff::0");
  test_addr_compare("0::3:2:1", <, "0::ffff:0.3.2.1");
  test_addr_compare("0::2:2:1", <, "0::ffff:0.3.2.1");
  test_addr_compare("0::ffff:0.3.2.1", >, "0::0:0:0");
  test_addr_compare("0::ffff:5.2.2.1", <, "::ffff:6.0.0.0"); /* XXXX wrong. */
  tor_addr_parse_mask_ports("[::ffff:2.3.4.5]", 0, &t1, NULL, NULL, NULL);
  tor_addr_parse_mask_ports("2.3.4.5", 0, &t2, NULL, NULL, NULL);
  test_assert(tor_addr_compare(&t1, &t2, CMP_SEMANTIC) == 0);
  tor_addr_parse_mask_ports("[::ffff:2.3.4.4]", 0, &t1, NULL, NULL, NULL);
  tor_addr_parse_mask_ports("2.3.4.5", 0, &t2, NULL, NULL, NULL);
  test_assert(tor_addr_compare(&t1, &t2, CMP_SEMANTIC) < 0);

  /* test compare_masked */
  test_addr_compare_masked("ffff::", ==, "ffff::0", 128);
  test_addr_compare_masked("ffff::", ==, "ffff::0", 64);
  test_addr_compare_masked("0::2:2:1", <, "0::8000:2:1", 81);
  test_addr_compare_masked("0::2:2:1", ==, "0::8000:2:1", 80);

  /* Test undecorated tor_addr_to_str */
  test_eq(AF_INET6, tor_addr_parse(&t1, "[123:45:6789::5005:11]"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 0);
  test_streq(p1, "123:45:6789::5005:11");
  test_eq(AF_INET, tor_addr_parse(&t1, "18.0.0.1"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 0);
  test_streq(p1, "18.0.0.1");

  /* Test decorated tor_addr_to_str */
  test_eq(AF_INET6, tor_addr_parse(&t1, "[123:45:6789::5005:11]"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "[123:45:6789::5005:11]");
  test_eq(AF_INET, tor_addr_parse(&t1, "18.0.0.1"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "18.0.0.1");

  /* Test buffer bounds checking of tor_addr_to_str */
  test_eq(AF_INET6, tor_addr_parse(&t1, "::")); /* 2 + \0 */
  test_eq_ptr(tor_addr_to_str(buf, &t1, 2, 0), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 3, 0), "::");
  test_eq_ptr(tor_addr_to_str(buf, &t1, 4, 1), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 5, 1), "[::]");

  test_eq(AF_INET6, tor_addr_parse(&t1, "2000::1337")); /* 10 + \0 */
  test_eq_ptr(tor_addr_to_str(buf, &t1, 10, 0), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 11, 0), "2000::1337");
  test_eq_ptr(tor_addr_to_str(buf, &t1, 12, 1), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 13, 1), "[2000::1337]");

  test_eq(AF_INET, tor_addr_parse(&t1, "1.2.3.4")); /* 7 + \0 */
  test_eq_ptr(tor_addr_to_str(buf, &t1, 7, 0), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 8, 0), "1.2.3.4");

  test_eq(AF_INET, tor_addr_parse(&t1, "255.255.255.255")); /* 15 + \0 */
  test_eq_ptr(tor_addr_to_str(buf, &t1, 15, 0), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 16, 0), "255.255.255.255");
  test_eq_ptr(tor_addr_to_str(buf, &t1, 15, 1), NULL); /* too short buf */
  test_streq(tor_addr_to_str(buf, &t1, 16, 1), "255.255.255.255");

  t1.family = AF_UNSPEC;
  test_eq_ptr(tor_addr_to_str(buf, &t1, sizeof(buf), 0), NULL);

  /* Test tor_addr_parse_PTR_name */
  i = tor_addr_parse_PTR_name(&t1, "Foobar.baz", AF_UNSPEC, 0);
  test_eq(0, i);
  i = tor_addr_parse_PTR_name(&t1, "Foobar.baz", AF_UNSPEC, 1);
  test_eq(0, i);
  i = tor_addr_parse_PTR_name(&t1, "9999999999999999999999999999.in-addr.arpa",
                              AF_UNSPEC, 1);
  test_eq(-1, i);
  i = tor_addr_parse_PTR_name(&t1, "1.0.168.192.in-addr.arpa",
                                         AF_UNSPEC, 1);
  test_eq(1, i);
  test_eq(tor_addr_family(&t1), AF_INET);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "192.168.0.1");
  i = tor_addr_parse_PTR_name(&t1, "192.168.0.99", AF_UNSPEC, 0);
  test_eq(0, i);
  i = tor_addr_parse_PTR_name(&t1, "192.168.0.99", AF_UNSPEC, 1);
  test_eq(1, i);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "192.168.0.99");
  memset(&t1, 0, sizeof(t1));
  i = tor_addr_parse_PTR_name(&t1,
                                         "0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(1, i);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "[9dee:effe:ebe1:beef:fedc:ba98:7654:3210]");
  /* Failing cases. */
  i = tor_addr_parse_PTR_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.a.b.c.d.e.f.0."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.X.0.0.0.0.9."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1, "32.1.1.in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1, ".in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1, "1.2.3.4.5.in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1, "1.2.3.4.5.in-addr.arpa",
                                         AF_INET6, 0);
  test_eq(i, -1);
  i = tor_addr_parse_PTR_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.a.b.c.d.e.0."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_INET, 0);
  test_eq(i, -1);

  /* === Test tor_addr_to_PTR_name */

  /* Stage IPv4 addr */
  memset(&sa_storage, 0, sizeof(sa_storage));
  sin = (struct sockaddr_in *)&sa_storage;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(0x7f010203); /* 127.1.2.3 */
  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin, NULL);

  /* Check IPv4 PTR - too short buffer */
  test_eq(tor_addr_to_PTR_name(rbuf, 1, &t1), -1);
  test_eq(tor_addr_to_PTR_name(rbuf,
                               strlen("3.2.1.127.in-addr.arpa") - 1,
                               &t1), -1);

  /* Check IPv4 PTR - valid addr */
  test_eq(tor_addr_to_PTR_name(rbuf, sizeof(rbuf), &t1),
          strlen("3.2.1.127.in-addr.arpa"));
  test_streq(rbuf, "3.2.1.127.in-addr.arpa");

  /* Invalid addr family */
  t1.family = AF_UNSPEC;
  test_eq(tor_addr_to_PTR_name(rbuf, sizeof(rbuf), &t1), -1);

  /* Stage IPv6 addr */
  memset(&sa_storage, 0, sizeof(sa_storage));
  sin6 = (struct sockaddr_in6 *)&sa_storage;
  sin6->sin6_family = AF_INET6;
  sin6->sin6_addr.s6_addr[0] = 0x80; /* 8000::abcd */
  sin6->sin6_addr.s6_addr[14] = 0xab;
  sin6->sin6_addr.s6_addr[15] = 0xcd;

  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin6, NULL);

  {
    const char* addr_PTR = "d.c.b.a.0.0.0.0.0.0.0.0.0.0.0.0."
      "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.ip6.arpa";

    /* Check IPv6 PTR - too short buffer */
    test_eq(tor_addr_to_PTR_name(rbuf, 0, &t1), -1);
    test_eq(tor_addr_to_PTR_name(rbuf, strlen(addr_PTR) - 1, &t1), -1);

    /* Check IPv6 PTR - valid addr */
    test_eq(tor_addr_to_PTR_name(rbuf, sizeof(rbuf), &t1),
            strlen(addr_PTR));
    test_streq(rbuf, addr_PTR);
  }

  /* XXXX turn this into a separate function; it's not all IPv6. */
  /* test tor_addr_parse_mask_ports */
  test_addr_mask_ports_parse("[::f]/17:47-95", AF_INET6,
                             0, 0, 0, 0x0000000f, 17, 47, 95);
  test_streq(p1, "::f");
  //test_addr_parse("[::fefe:4.1.1.7/120]:999-1000");
  //test_addr_parse_check("::fefe:401:107", 120, 999, 1000);
  test_addr_mask_ports_parse("[::ffff:4.1.1.7]/120:443", AF_INET6,
                             0, 0, 0x0000ffff, 0x04010107, 120, 443, 443);
  test_streq(p1, "::ffff:4.1.1.7");
  test_addr_mask_ports_parse("[abcd:2::44a:0]:2-65000", AF_INET6,
                             0xabcd0002, 0, 0, 0x044a0000, 128, 2, 65000);

  test_streq(p1, "abcd:2::44a:0");
  /* Try some long addresses. */
  r=tor_addr_parse_mask_ports("[ffff:1111:1111:1111:1111:1111:1111:1111]",
                              0, &t1, NULL, NULL, NULL);
  test_assert(r == AF_INET6);
  r=tor_addr_parse_mask_ports("[ffff:1111:1111:1111:1111:1111:1111:11111]",
                              0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[ffff:1111:1111:1111:1111:1111:1111:1111:1]",
                              0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports(
         "[ffff:1111:1111:1111:1111:1111:1111:ffff:"
         "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:"
         "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:"
         "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]",
         0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  /* Try some failing cases. */
  r=tor_addr_parse_mask_ports("[fefef::]/112", 0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[fefe::/112", 0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[fefe::", 0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[fefe::X]", 0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("efef::/112", 0, &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f:f:f:f::]",0,&t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[::f:f:f:f:f:f:f:f]",0,&t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f:f:f:f:f]",0,&t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f::]/fred",0,&t1,&mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f::]/255.255.0.0",
                              0,&t1, NULL, NULL, NULL);
  test_assert(r == -1);
  /* This one will get rejected because it isn't a pure prefix. */
  r=tor_addr_parse_mask_ports("1.1.2.3/255.255.64.0",0,&t1, &mask,NULL,NULL);
  test_assert(r == -1);
  /* Test for V4-mapped address with mask < 96.  (arguably not valid) */
  r=tor_addr_parse_mask_ports("[::ffff:1.1.2.2/33]",0,&t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("1.1.2.2/33",0,&t1, &mask, NULL, NULL);
  test_assert(r == -1);
  /* Try extended wildcard addresses with out TAPMP_EXTENDED_STAR*/
  r=tor_addr_parse_mask_ports("*4",0,&t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("*6",0,&t1, &mask, NULL, NULL);
  test_assert(r == -1);
#if 0
  /* Try a mask with a wildcard. */
  r=tor_addr_parse_mask_ports("*/16",0,&t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("*4/16",TAPMP_EXTENDED_STAR,
                              &t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("*6/30",TAPMP_EXTENDED_STAR,
                              &t1, &mask, NULL, NULL);
  test_assert(r == -1);
#endif
  /* Basic mask tests*/
  r=tor_addr_parse_mask_ports("1.1.2.2/31",0,&t1, &mask, NULL, NULL);
  test_assert(r == AF_INET);
  tt_int_op(mask,==,31);
  tt_int_op(tor_addr_family(&t1),==,AF_INET);
  tt_int_op(tor_addr_to_ipv4h(&t1),==,0x01010202);
  r=tor_addr_parse_mask_ports("3.4.16.032:1-2",0,&t1, &mask, &port1, &port2);
  test_assert(r == AF_INET);
  tt_int_op(mask,==,32);
  tt_int_op(tor_addr_family(&t1),==,AF_INET);
  tt_int_op(tor_addr_to_ipv4h(&t1),==,0x03041020);
  test_assert(port1 == 1);
  test_assert(port2 == 2);
  r=tor_addr_parse_mask_ports("1.1.2.3/255.255.128.0",0,&t1, &mask,NULL,NULL);
  test_assert(r == AF_INET);
  tt_int_op(mask,==,17);
  tt_int_op(tor_addr_family(&t1),==,AF_INET);
  tt_int_op(tor_addr_to_ipv4h(&t1),==,0x01010203);
  r=tor_addr_parse_mask_ports("[efef::]/112",0,&t1, &mask, &port1, &port2);
  test_assert(r == AF_INET6);
  test_assert(port1 == 1);
  test_assert(port2 == 65535);
  /* Try regular wildcard behavior without TAPMP_EXTENDED_STAR */
  r=tor_addr_parse_mask_ports("*:80-443",0,&t1,&mask,&port1,&port2);
  tt_int_op(r,==,AF_INET); /* Old users of this always get inet */
  tt_int_op(tor_addr_family(&t1),==,AF_INET);
  tt_int_op(tor_addr_to_ipv4h(&t1),==,0);
  tt_int_op(mask,==,0);
  tt_int_op(port1,==,80);
  tt_int_op(port2,==,443);
  /* Now try wildcards *with* TAPMP_EXTENDED_STAR */
  r=tor_addr_parse_mask_ports("*:8000-9000",TAPMP_EXTENDED_STAR,
                              &t1,&mask,&port1,&port2);
  tt_int_op(r,==,AF_UNSPEC);
  tt_int_op(tor_addr_family(&t1),==,AF_UNSPEC);
  tt_int_op(mask,==,0);
  tt_int_op(port1,==,8000);
  tt_int_op(port2,==,9000);
  r=tor_addr_parse_mask_ports("*4:6667",TAPMP_EXTENDED_STAR,
                              &t1,&mask,&port1,&port2);
  tt_int_op(r,==,AF_INET);
  tt_int_op(tor_addr_family(&t1),==,AF_INET);
  tt_int_op(tor_addr_to_ipv4h(&t1),==,0);
  tt_int_op(mask,==,0);
  tt_int_op(port1,==,6667);
  tt_int_op(port2,==,6667);
  r=tor_addr_parse_mask_ports("*6",TAPMP_EXTENDED_STAR,
                              &t1,&mask,&port1,&port2);
  tt_int_op(r,==,AF_INET6);
  tt_int_op(tor_addr_family(&t1),==,AF_INET6);
  tt_assert(tor_mem_is_zero((const char*)tor_addr_to_in6_addr32(&t1), 16));
  tt_int_op(mask,==,0);
  tt_int_op(port1,==,1);
  tt_int_op(port2,==,65535);

  /* make sure inet address lengths >= max */
  test_assert(INET_NTOA_BUF_LEN >= sizeof("255.255.255.255"));
  test_assert(TOR_ADDR_BUF_LEN >=
              sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"));

  test_assert(sizeof(tor_addr_t) >= sizeof(struct in6_addr));

done:
  ;
}

static smartlist_t *
mocked_get_interface_addresses_raw(int severity)
{
  smartlist_t *pretend_addrs = smartlist_new();
  tor_addr_t *addr = NULL;
  (void) severity;
  /* Make a loopback ipv4 addr (127.0.0.1) */
  addr = tor_calloc(1, sizeof(*addr));
  tor_addr_parse(addr, "127.0.0.1");
  smartlist_add(pretend_addrs, addr);
  /* Make a multicast ipv4 addr (255.255.255.255) */
  addr = tor_calloc(1, sizeof(*addr));
  tor_addr_parse(addr, "255.255.255.255");
  smartlist_add(pretend_addrs, addr);
  /* Make an LAN ipv4 addr (192.168.1.1) */
  addr = tor_calloc(1, sizeof(*addr));
  tor_addr_parse(addr, "192.168.1.1");
  smartlist_add(pretend_addrs, addr);
  /* Make an WAN ipv4 addr (38.229.72.14) */
  addr = tor_calloc(1, sizeof(*addr));
  tor_addr_parse(addr, "38.229.72.14");
  smartlist_add(pretend_addrs, addr);
  /* Make an WAN ipv6 addr ([2620:0:6b0:b:1a1a:0:26e5:480c]) */
  addr = tor_calloc(1, sizeof(*addr));
  tor_addr_parse(addr, "2620:0:6b0:b:1a1a:0:26e5:480c");
  smartlist_add(pretend_addrs, addr);
  return pretend_addrs;
}

static smartlist_t *
mocked_get_interface_addresses_raw_null(int severity)
{
  (void) severity;
  return NULL;
}

static smartlist_t *
mocked_get_interface_addresses_raw_empty(int severity)
{
  smartlist_t *pretend_addrs = smartlist_new();
  (void) severity;
  return pretend_addrs;
}

static smartlist_t *
mocked_get_interface_address6_null(int severity, sa_family_t family)
{
  (void) severity;
  (void) family;
  return NULL;
}

static smartlist_t *
mocked_get_interface_address6_empty(int severity, sa_family_t family)
{
  smartlist_t *pretend_addrs = smartlist_new();
  (void) severity;
  (void) family;
  return pretend_addrs;
}

#define check_addrlist_fam(list, fam) do {                        \
  if (list != NULL) {                                             \
    SMARTLIST_FOREACH(ipv4s, const tor_addr_t *, a,               \
        tt_int_op(tor_addr_family(a), ==, AF_INET));              \
  }} while(0)
static void
test_get_interface_address6(void *data)
{
  smartlist_t *ipv6s = NULL;
  smartlist_t *ipv4s = NULL;
  (void) data; /* Unused param */
  MOCK(get_interface_addresses_raw, mocked_get_interface_addresses_raw);
  /* get ipv4 addrs using the get_interface_address6 fn */
  ipv4s = get_interface_address6(LOG_DEBUG, AF_INET);
  check_addrlist_fam(ipv4s, AF_INET);
  /* Get ipv6 addrs */
  ipv6s = get_interface_address6(LOG_DEBUG, AF_INET6);
  check_addrlist_fam(ipv6s, AF_INET6);
  UNMOCK(get_interface_addresses_raw);
  /* Use the "alternate method" */
  MOCK(get_interface_addresses_raw, mocked_get_interface_addresses_raw_null);
  /* get ipv4 addrs using the get_interface_address6 fn */
  ipv4s = get_interface_address6(LOG_DEBUG, AF_INET);
  check_addrlist_fam(ipv4s, AF_INET);
  /* Get ipv6 addrs */
  ipv6s = get_interface_address6(LOG_DEBUG, AF_INET6);
  check_addrlist_fam(ipv6s, AF_INET6);
  /* Test that we can't get addrs from AF_UNSPEC via the dumb method */
  ipv6s = get_interface_address6(LOG_DEBUG, AF_UNSPEC);
  tt_ptr_op(ipv6s, ==, NULL);
  UNMOCK(get_interface_addresses_raw);
  /* Use the "alternate method" */
  MOCK(get_interface_addresses_raw, mocked_get_interface_addresses_raw_empty);
  /* These should return NULL */
  ipv4s = get_interface_address6(LOG_DEBUG, AF_INET);
  tt_ptr_op(ipv4s, ==, NULL);
  ipv6s = get_interface_address6(LOG_DEBUG, AF_INET6);
  tt_ptr_op(ipv6s, ==, NULL);
  ipv6s = get_interface_address6(LOG_DEBUG, AF_UNSPEC);
  tt_ptr_op(ipv6s, ==, NULL);
done:
  if(ipv6s) SMARTLIST_FOREACH(ipv6s, tor_addr_t *, a, tor_free(a));
  smartlist_free(ipv6s);
  if(ipv4s) SMARTLIST_FOREACH(ipv4s, tor_addr_t *, a, tor_free(a));
  smartlist_free(ipv4s);
  UNMOCK(get_interface_addresses_raw);
}
#undef check_addrlist_fam


/** Test tor_addr_port_parse(). */
static void
test_addr_parse(void)
{
  int r;
  tor_addr_t addr;
  char buf[TOR_ADDR_BUF_LEN];
  uint16_t port = 0;

  /* Correct call. */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "192.0.2.1:1234",
                         &addr, &port);
  test_assert(r == 0);
  tor_addr_to_str(buf, &addr, sizeof(buf), 0);
  test_streq(buf, "192.0.2.1");
  test_eq(port, 1234);

  /* Domain name. */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "torproject.org:1234",
                         &addr, &port);
  test_assert(r == -1);

  /* Only IP. */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "192.0.2.2",
                         &addr, &port);
  test_assert(r == -1);

  /* Bad port. */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "192.0.2.2:66666",
                         &addr, &port);
  test_assert(r == -1);

  /* Only domain name */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "torproject.org",
                         &addr, &port);
  test_assert(r == -1);

  /* Bad IP address */
  r= tor_addr_port_parse(LOG_DEBUG,
                         "192.0.2:1234",
                         &addr, &port);
  test_assert(r == -1);

 done:
  ;
}

static void
update_difference(int ipv6, uint8_t *d,
                  const tor_addr_t *a, const tor_addr_t *b)
{
  const int n_bytes = ipv6 ? 16 : 4;
  uint8_t a_tmp[4], b_tmp[4];
  const uint8_t *ba, *bb;
  int i;

  if (ipv6) {
    ba = tor_addr_to_in6_addr8(a);
    bb = tor_addr_to_in6_addr8(b);
  } else {
    set_uint32(a_tmp, tor_addr_to_ipv4n(a));
    set_uint32(b_tmp, tor_addr_to_ipv4n(b));
    ba = a_tmp; bb = b_tmp;
  }

  for (i = 0; i < n_bytes; ++i) {
    d[i] |= ba[i] ^ bb[i];
  }
}

static void
test_virtaddrmap(void *data)
{
  /* Let's start with a bunch of random addresses. */
  int ipv6, bits, iter, b;
  virtual_addr_conf_t cfg[2];
  uint8_t bytes[16];

  (void)data;

  tor_addr_parse(&cfg[0].addr, "64.65.0.0");
  tor_addr_parse(&cfg[1].addr, "3491:c0c0::");

  for (ipv6 = 0; ipv6 <= 1; ++ipv6) {
    for (bits = 0; bits < 18; ++bits) {
      tor_addr_t last_a;
      cfg[ipv6].bits = bits;
      memset(bytes, 0, sizeof(bytes));
      tor_addr_copy(&last_a, &cfg[ipv6].addr);
      /* Generate 128 addresses with each addr/bits combination. */
      for (iter = 0; iter < 128; ++iter) {
        tor_addr_t a;

        get_random_virtual_addr(&cfg[ipv6], &a);
        //printf("%s\n", fmt_addr(&a));
        /* Make sure that the first b bits match the configured network */
        tt_int_op(0, ==, tor_addr_compare_masked(&a, &cfg[ipv6].addr,
                                                 bits, CMP_EXACT));

        /* And track which bits have been different between pairs of
         * addresses */
        update_difference(ipv6, bytes, &last_a, &a);
      }

      /* Now make sure all but the first 'bits' bits of bytes are true */
      for (b = bits+1; b < (ipv6?128:32); ++b) {
        tt_assert(1 & (bytes[b/8] >> (7-(b&7))));
      }
    }
  }

 done:
  ;
}

static void
test_addr_localname(void *arg)
{
  (void)arg;
  tt_assert(tor_addr_hostname_is_local("localhost"));
  tt_assert(tor_addr_hostname_is_local("LOCALHOST"));
  tt_assert(tor_addr_hostname_is_local("LocalHost"));
  tt_assert(tor_addr_hostname_is_local("local"));
  tt_assert(tor_addr_hostname_is_local("LOCAL"));
  tt_assert(tor_addr_hostname_is_local("here.now.local"));
  tt_assert(tor_addr_hostname_is_local("here.now.LOCAL"));

  tt_assert(!tor_addr_hostname_is_local(" localhost"));
  tt_assert(!tor_addr_hostname_is_local("www.torproject.org"));
 done:
  ;
}

static void
test_addr_dup_ip(void *arg)
{
  char *v = NULL;
  (void)arg;
#define CHECK(ip, s) do {                         \
    v = tor_dup_ip(ip);                           \
    tt_str_op(v,==,(s));                          \
    tor_free(v);                                  \
  } while (0)

  CHECK(0xffffffff, "255.255.255.255");
  CHECK(0x00000000, "0.0.0.0");
  CHECK(0x7f000001, "127.0.0.1");
  CHECK(0x01020304, "1.2.3.4");

#undef CHECK
 done:
  tor_free(v);
}

static void
test_addr_sockaddr_to_str(void *arg)
{
  char *v = NULL;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr_storage ss;
#ifdef HAVE_SYS_UN_H
  struct sockaddr_un sun;
#endif
#define CHECK(sa, s) do {                                       \
    v = tor_sockaddr_to_str((const struct sockaddr*) &(sa));    \
    tt_str_op(v,==,(s));                                        \
    tor_free(v);                                                \
  } while (0)
  (void)arg;

  memset(&ss,0,sizeof(ss));
  ss.ss_family = AF_UNSPEC;
  CHECK(ss, "unspec");

  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(0x7f808001);
  sin.sin_port = htons(1234);
  CHECK(sin, "127.128.128.1:1234");

#ifdef HAVE_SYS_UN_H
  memset(&sun,0,sizeof(sun));
  sun.sun_family = AF_UNIX;
  strlcpy(sun.sun_path, "/here/is/a/path", sizeof(sun.sun_path));
  CHECK(sun, "unix:/here/is/a/path");
#endif

  memset(&sin6,0,sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  memcpy(sin6.sin6_addr.s6_addr, "\x20\x00\x00\x00\x00\x00\x00\x00"
                                 "\x00\x1a\x2b\x3c\x4d\x5e\x00\x01", 16);
  sin6.sin6_port = htons(1234);
  CHECK(sin6, "[2000::1a:2b3c:4d5e:1]:1234");

 done:
  tor_free(v);
}

static void
test_addr_is_loopback(void *data)
{
  static const struct loopback_item {
    const char *name;
    int is_loopback;
  } loopback_items[] = {
    { "::1", 1 },
    { "127.0.0.1", 1 },
    { "127.99.100.101", 1 },
    { "128.99.100.101", 0 },
    { "8.8.8.8", 0 },
    { "0.0.0.0", 0 },
    { "::2", 0 },
    { "::", 0 },
    { "::1.0.0.0", 0 },
    { NULL, 0 }
  };

  int i;
  tor_addr_t addr;
  (void)data;

  for (i=0; loopback_items[i].name; ++i) {
    tt_int_op(tor_addr_parse(&addr, loopback_items[i].name), >=, 0);
    tt_int_op(tor_addr_is_loopback(&addr), ==, loopback_items[i].is_loopback);
  }

  tor_addr_make_unspec(&addr);
  tt_int_op(tor_addr_is_loopback(&addr), ==, 0);

 done:
  ;
}


static void
test_get_first_address_by_af(void *data)
{
  smartlist_t *addrlist = smartlist_new();
  tor_addr_t *tmpaddr = NULL;
  const tor_addr_t *resaddr = NULL; /* variable ptr to const addr! */
  (void) (data); /* Unused param */

  /* Add 3 addresses to smartlist: two IPv4, one IPv6. */
  tmpaddr = tor_calloc(1, sizeof(*tmpaddr));
  tor_addr_parse(tmpaddr, "13.11.9.7");
  smartlist_add(addrlist, tmpaddr);

  tmpaddr = tor_calloc(1, sizeof(*tmpaddr));
  tor_addr_parse(tmpaddr, "127.0.0.1");
  tmpaddr->family = AF_UNSPEC;
  smartlist_add(addrlist, tmpaddr);

  tmpaddr = tor_calloc(1, sizeof(*tmpaddr));
  tor_addr_parse(tmpaddr, "2001:0db8:85a3:0042:1000:8a2e:0370:7334");
  smartlist_add(addrlist, tmpaddr);

  resaddr = get_first_address_by_af(addrlist, AF_INET);
  /* Should be the first addr, 13.11.9.7 */
  tt_assert(tor_addr_eq(resaddr, (const tor_addr_t*) smartlist_get(addrlist, 0)));
  tt_int_op(tor_addr_family(resaddr), ==, AF_INET);

  resaddr = get_first_address_by_af(addrlist, AF_INET6);
  /* Should be the IPv6 addr */
  tt_assert(tor_addr_eq(resaddr, (tor_addr_t*) smartlist_get(addrlist, 2)));
  tt_int_op(tor_addr_family(resaddr), ==, AF_INET6);

  done:
    if (addrlist) {
        SMARTLIST_FOREACH(addrlist, tor_addr_t *, a, tor_free(a));
        smartlist_free(addrlist);
    }
}

static void
test_get_stable_interface_address6(void *data)
{
  int res = 0;
  tor_addr_t *addr = tor_calloc(1, sizeof(*addr));
  tor_addr_t *old_addr = tor_calloc(1, sizeof(*old_addr));
  (void) data;
  MOCK(get_interface_addresses_raw, mocked_get_interface_addresses_raw);
  /* Don't have an addr, ensure 1 is returned */
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET, addr);
  tt_int_op(res, ==, 1);
  /* Should have an addr, ensure */
  memcpy(old_addr, addr, sizeof(*addr));
  memset(addr, 0, sizeof(*addr));
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET, addr);
  tt_int_op(res, ==, 0);
  tt_assert(tor_addr_eq(addr, old_addr));
  /****************** Do it all again with AF_INET6 *******************/
  memset(addr, 0, sizeof(*addr));
  memset(old_addr, 0, sizeof(*old_addr));
  /* Don't have an addr, ensure 1 is returned */
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET6, addr);
  tt_int_op(res, ==, 1);
  /* Should have an addr, ensure */
  memcpy(old_addr, addr, sizeof(*addr));
  memset(addr, 0, sizeof(*addr));
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET6, addr);
  tt_int_op(res, ==, 0);
  tt_assert(tor_addr_eq(addr, old_addr));
  /******************* Try with AF_UNSPEC & AF_UNIX ******************/
  /* Both of these should return -1, as get_stable_interface_address6 doesn't
   * support these address types
   */
  memset(addr, 0, sizeof(*addr));
  res = get_stable_interface_address6(LOG_DEBUG, AF_UNSPEC, addr);
  tt_int_op(res, ==, -1);
  memset(addr, 0, sizeof(*addr));
  res = get_stable_interface_address6(LOG_DEBUG, AF_UNIX, addr);
  tt_int_op(res, ==, -1);
  /* Try mocking out the get_interface_address6 funtion this time */
  MOCK(get_interface_address6, mocked_get_interface_address6_empty);
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET, addr);
  tt_int_op(res, ==, -1);
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET6, addr);
  tt_int_op(res, ==, -1);
  UNMOCK(get_interface_address6);
  MOCK(get_interface_address6, mocked_get_interface_address6_null);
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET, addr);
  tt_int_op(res, ==, -1);
  res = get_stable_interface_address6(LOG_DEBUG, AF_INET6, addr);
  tt_int_op(res, ==, -1);
  UNMOCK(get_interface_address6);
done:
  tor_free(addr);
  tor_free(old_addr);
  UNMOCK(get_interface_addresses_raw);
  UNMOCK(get_interface_address6);
}

static void
test_addr_clone (void *data)
{
  tor_addr_t *src, *dest;
  (void) data;
  src = tor_malloc(sizeof(*src));
  dest = NULL;
  /* Make a tor_addr_t with valid params */
  tor_addr_parse(src, "123.12.3.123");
  /* clone the addr to dest */
  dest = tor_addr_clone(src);
  /* test equality */
  tt_ptr_op(src, !=, dest);
  tt_assert(tor_addr_eq(src, dest));
done:
  tor_free(src);
  tor_free(dest);
}

static void
test_addr_make_null (void *data)
{
  tor_addr_t *addr = tor_malloc(sizeof(*addr));
  tor_addr_t *refaddr = tor_malloc(sizeof(*refaddr));
  (void) data;
  /* Make an ipv4 addr, and null it out */
  tor_addr_parse(addr, "123.12.3.123");
  tor_addr_parse(refaddr, "0.0.0.0"); /* NULL ipv4 addr */
  tor_addr_make_null(addr, AF_INET);
  tt_assert(tor_addr_eq(addr, refaddr));
  tt_int_op(addr->family, ==, AF_INET);
  /* Make an ipv6 addr, and null it out */
  tor_addr_parse(addr, "2001:0db8:85a3:0042:1000:8a2e:0370:7334");
  tor_addr_parse(refaddr, "[::]"); /* NULL inet6 addr */
  tor_addr_make_null(addr, AF_INET6);
  tt_assert(tor_addr_eq(addr, refaddr));
  tt_int_op(addr->family, ==, AF_INET6);
done:
  tor_free(addr);
  tor_free(refaddr);
}

static void
test_addr_port_copy (void *data)
{
  tor_addr_port_t srcaddr;
  tor_addr_port_t destaddr;
  (void) data;
  /* Test with an ipv4 addr with port*/
  tor_addr_port_parse(0, "123.12.3.123:102", &srcaddr.addr, &srcaddr.port);
  tor_addr_make_null(&destaddr.addr, AF_INET);
  destaddr.port = 0;
  tor_addr_port_copy(&destaddr, &srcaddr);
  tt_assert(tor_addr_eq(&srcaddr.addr, &destaddr.addr));
  tt_int_op(srcaddr.port, ==, destaddr.port);
  /* Test with an ipv4 addr without port*/
  tor_addr_port_parse(0, "123.12.3.123", &srcaddr.addr, &srcaddr.port);
  tor_addr_make_null(&destaddr.addr, AF_INET);
  destaddr.port = 0;
  tor_addr_port_copy(&destaddr, &srcaddr);
  tt_assert(tor_addr_eq(&srcaddr.addr, &destaddr.addr));
  tt_int_op(srcaddr.port, ==, destaddr.port);
  /* Test with an ipv4 addr with port*/
  tor_addr_port_parse(0, "2001:0db8:85a3:0042:1000:8a2e:0370:7334:102",
      &srcaddr.addr, &srcaddr.port);
  tor_addr_make_null(&destaddr.addr, AF_INET);
  destaddr.port = 0;
  tor_addr_port_copy(&destaddr, &srcaddr);
  tt_assert(tor_addr_eq(&srcaddr.addr, &destaddr.addr));
  tt_int_op(srcaddr.port, ==, destaddr.port);
  /* Test with an ipv4 addr without port*/
  tor_addr_port_parse(0, "2001:0db8:85a3:0042:1000:8a2e:0370:7334",
      &srcaddr.addr, &srcaddr.port);
  tor_addr_make_null(&destaddr.addr, AF_INET);
  destaddr.port = 0;
  tor_addr_port_copy(&destaddr, &srcaddr);
  tt_assert(tor_addr_eq(&srcaddr.addr, &destaddr.addr));
  tt_int_op(srcaddr.port, ==, destaddr.port);
done:
  ;
}
#define ADDR_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_addr_ ## name }

struct testcase_t addr_tests[] = {
  ADDR_LEGACY(basic),
  ADDR_LEGACY(ip6_helpers),
  ADDR_LEGACY(parse),
  { "virtaddr", test_virtaddrmap, 0, NULL, NULL },
  { "localname", test_addr_localname, 0, NULL, NULL },
  { "dup_ip", test_addr_dup_ip, 0, NULL, NULL },
  { "sockaddr_to_str", test_addr_sockaddr_to_str, 0, NULL, NULL },
  { "is_loopback", test_addr_is_loopback, 0, NULL, NULL },
  { "get_first_addr_by_af", test_get_first_address_by_af, 0, NULL, NULL},
  { "get_interface_address6", test_get_interface_address6, 0, NULL, NULL},
  { "get_stable_interface_address6", test_get_stable_interface_address6, 0, NULL, NULL},
  { "addr_clone", test_addr_clone, 0, NULL, NULL},
  { "addr_make_null", test_addr_make_null, 0, NULL, NULL},
  { "addr_port_copy", test_addr_port_copy, 0, NULL, NULL},
  END_OF_TESTCASES
};

