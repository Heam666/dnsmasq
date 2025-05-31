/* dnsmasq is Copyright (c) 2000-2024 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"
#define XDNS_NULL_MAC "00:00:00:00:00:00"

unsigned char *find_pseudoheader(struct dns_header *header, size_t plen, size_t  *len, unsigned char **p, int *is_sign, int *is_last)
{
  /* See if packet has an RFC2671 pseudoheader, and if so return a pointer to it. 
     also return length of pseudoheader in *len and pointer to the UDP size in *p
     Finally, check to see if a packet is signed. If it is we cannot change a single bit before
     forwarding. We look for TSIG in the addition section, and TKEY queries (for GSS-TSIG) */
  
  int i, arcount = ntohs(header->arcount);
  unsigned char *ansp = (unsigned char *)(header+1);
  unsigned short rdlen, type, class;
  unsigned char *ret = NULL;

  if (is_sign)
    {
      *is_sign = 0;

      if (OPCODE(header) == QUERY)
	{
	  for (i = ntohs(header->qdcount); i != 0; i--)
	    {
	      if (!(ansp = skip_name(ansp, header, plen, 4)))
		return NULL;
	      
	      GETSHORT(type, ansp); 
	      GETSHORT(class, ansp);
	      
	      if (class == C_IN && type == T_TKEY)
		*is_sign = 1;
	    }
	}
    }
  else
    {
      if (!(ansp = skip_questions(header, plen)))
	return NULL;
    }
    
  if (arcount == 0)
    return NULL;
  
  if (!(ansp = skip_section(ansp, ntohs(header->ancount) + ntohs(header->nscount), header, plen)))
    return NULL; 
  
  for (i = 0; i < arcount; i++)
    {
      unsigned char *save, *start = ansp;
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 

      GETSHORT(type, ansp);
      save = ansp;
      GETSHORT(class, ansp);
      ansp += 4; /* TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
      if (type == T_OPT)
	{
	  if (len)
	    *len = ansp - start;

	  if (p)
	    *p = save;
	  
	  if (is_last)
	    *is_last = (i == arcount-1);

	  ret = start;
	}
      else if (is_sign && 
	       i == arcount - 1 && 
	       class == C_ANY && 
	       type == T_TSIG)
	*is_sign = 1;
    }
  
  return ret;
}
 

/* replace == 2 ->delete existing option only. */
size_t add_pseudoheader(struct dns_header *header, size_t plen, unsigned char *limit, 
			unsigned short udp_sz, int optno, unsigned char *opt, size_t optlen, int set_do, int replace)
{ 
  unsigned char *lenp, *datap, *p, *udp_len, *buff = NULL;
  int rdlen = 0, is_sign, is_last;
  unsigned short flags = set_do ? 0x8000 : 0, rcode = 0;

  p = find_pseudoheader(header, plen, NULL, &udp_len, &is_sign, &is_last);
  
  if (is_sign)
    return plen;

  if (p)
    {
      /* Existing header */
      int i;
      unsigned short code, len;

      p = udp_len;
      GETSHORT(udp_sz, p);
      GETSHORT(rcode, p);
      GETSHORT(flags, p);

      if (set_do)
	{
	  p -= 2;
	  flags |= 0x8000;
	  PUTSHORT(flags, p);
	}

      lenp = p;
      GETSHORT(rdlen, p);
      if (!CHECK_LEN(header, p, plen, rdlen))
	return plen; /* bad packet */
      datap = p;

       /* no option to add */
      if (optno == 0)
	return plen;
      	  
      /* check if option already there */
      for (i = 0; i + 4 < rdlen;)
	{
	  GETSHORT(code, p);
	  GETSHORT(len, p);
	  
	  /* malformed option, delete the whole OPT RR and start again. */
	  if (i + 4 + len > rdlen)
	    {
	      rdlen = 0;
	      is_last = 0;
	      break;
	    }
	  
	  if (code == optno)
	    {
	      if (replace == 0)
		return plen;

	      /* delete option if we're to replace it. */
	      p -= 4;
	      rdlen -= len + 4;
	      memmove(p, p+len+4, rdlen - i);
	      PUTSHORT(rdlen, lenp);
	      lenp -= 2;
	    }
	  else
	    {
	      p += len;
	      i += len + 4;
	    }
	}

      /* If we're going to extend the RR, it has to be the last RR in the packet */
      if (!is_last)
	{
	  /* First, take a copy of the options. */
	  if (rdlen != 0 && (buff = whine_malloc(rdlen)))
	    memcpy(buff, datap, rdlen);	      
	  
	  /* now, delete OPT RR */
	  rrfilter(header, &plen, RRFILTER_EDNS0);
	  
	  /* Now, force addition of a new one */
	  p = NULL;	  
	}
    }
  
  if (!p)
    {
      /* We are (re)adding the pseudoheader */
      if (!(p = skip_questions(header, plen)) ||
	  !(p = skip_section(p, 
			     ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount), 
			     header, plen)) ||
	  p + 11 > limit)
	{
	  free(buff);
	  return plen; /* bad packet */
	}
      
      *p++ = 0; /* empty name */
      PUTSHORT(T_OPT, p);
      PUTSHORT(udp_sz, p); /* max packet length, 512 if not given in EDNS0 header */
      PUTSHORT(rcode, p);    /* extended RCODE and version */
      PUTSHORT(flags, p); /* DO flag */
      lenp = p;
      PUTSHORT(rdlen, p);    /* RDLEN */
      datap = p;
      /* Copy back any options */
      if (buff)
	{
          if (p + rdlen > limit)
          {
            free(buff);
            return plen; /* Too big */
          }
	  memcpy(p, buff, rdlen);
	  free(buff);
	  p += rdlen;
	}
      
      /* Only bump arcount if RR is going to fit */ 
      if (((ssize_t)optlen) <= (limit - (p + 4)))
	header->arcount = htons(ntohs(header->arcount) + 1);
    }
  
  if (((ssize_t)optlen) > (limit - (p + 4)))
    return plen; /* Too big */
  
  /* Add new option */
  if (optno != 0 && replace != 2)
    {
      if (p + 4 > limit)
       return plen; /* Too big */
      PUTSHORT(optno, p);
      PUTSHORT(optlen, p);
      if (p + optlen > limit)
       return plen; /* Too big */
      memcpy(p, opt, optlen);
      p += optlen;  
      PUTSHORT(p - datap, lenp);
    }
  return p - (unsigned char *)header;
}

size_t add_do_bit(struct dns_header *header, size_t plen, unsigned char *limit)
{
  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, 0, NULL, 0, 1, 0);
}

static unsigned char char64(unsigned char c)
{
  return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[c & 0x3f];
}

static void encoder(unsigned char *in, char *out)
{
  out[0] = char64(in[0]>>2);
  out[1] = char64((in[0]<<4) | (in[1]>>4));
  out[2] = char64((in[1]<<2) | (in[2]>>6));
  out[3] = char64(in[2]);
}

/* XDNS - Add cpe tag for XDNS if found */
static size_t add_cpe_tag(struct dns_header *header, size_t plen, unsigned char *limit, union mysockaddr *l3, time_t now)
{
       unsigned char mac[DHCP_CHADDR_MAX] = {0};
       int maclen = 0;
       char strmac[REC_ADDR_MAX] = {0};
       memset(strmac, 0, REC_ADDR_MAX);

       struct dnsoverride_record* dnsrec = NULL;
       unsigned char* cpetag = NULL;

       if ((maclen = find_mac(l3, mac, 1, now)) != 0)
       {
               print_mac(strmac, mac, maclen);

               dnsrec = get_dnsoverride_record(strmac);
               if(!dnsrec)
                       dnsrec = get_dnsoverride_defaultrecord();

               if(dnsrec && dnsrec->cpetag[0])
               {
                       //my_syslog(LOG_WARNING, _("#### XDNS add_cpe_tag() - found cpetag: %s"), dnsrec->cpetag);
                       cpetag = dnsrec->cpetag;
               }
               else
               {
                       my_syslog(LOG_INFO, _("#### XDNS add_cpe_tag() Could not find cpetag for mac %s"), strmac);
               }
       }

       //if cpetag not found try to use the one from dnsmasq options
       if(cpetag == NULL)
       {
               cpetag = (unsigned char *)daemon->dns_client_id;
       }

       // if no cpetag found return. Don't call add header.
       if(cpetag == NULL)
       {
               my_syslog(LOG_INFO, _("#### XDNS : no cpetag found in dnsmasq config"));
               return plen;
       }

       my_syslog(LOG_INFO, _("### XDNS - add cpe tag \'%s\' to edns0 header for mac [%s]"), cpetag, strmac);
       return add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_NOMCPEID, cpetag, strlen(cpetag), 0, 1);
}
//</XDNS>

/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */
static size_t add_dns_client(struct dns_header *header, size_t plen, unsigned char *limit,
			     union mysockaddr *l3, time_t now, int *cacheablep)
{
  int replace = 0, maclen = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
  char encode[18]; /* handle 6 byte MACs ONLY */

  if ((option_bool(OPT_MAC_B64) || option_bool(OPT_MAC_HEX)) && (maclen = find_mac(l3, mac, 1, now)) == 6)
    {
      if (option_bool(OPT_STRIP_MAC))
	 replace = 1;
       *cacheablep = 0;
    
       if (option_bool(OPT_MAC_HEX))
	 print_mac(encode, mac, maclen);
       else
	 {
	   encoder(mac, encode);
	   encoder(mac+3, encode+4);
	   encode[8] = 0;
	 }
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;

  if (replace != 0 || maclen == 6)
    plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_NOMDEVICEID, (unsigned char *)encode, strlen(encode), 0, replace);

  return plen;
}

// XDNS
void set_option_dnsoverride()
{
  if (OPT_DNS_OVERRIDE < 32)
    daemon->options[0] |= 1u << OPT_DNS_OVERRIDE;
  else
    daemon->options[1] |= 1u << (OPT_DNS_OVERRIDE - 32);
}

// XDNS
void reset_option_dnsoverride()
{
  if (OPT_DNS_OVERRIDE < 32)
    daemon->options[0] &= ~(1u << OPT_DNS_OVERRIDE);
  else
    daemon->options[1] &= ~(1u << (OPT_DNS_OVERRIDE - 32));
}

// XDNS
static size_t add_xdns_server(struct dns_header *header, size_t plen, unsigned char *limit, union mysockaddr *l3, time_t now)
{
   int maclen = 0;
   unsigned char mac[DHCP_CHADDR_MAX];

   if(daemon->use_xdns_refactor_code)
   {
       // find mac from socket addr
     if ((maclen = find_mac(l3, mac, 1, now)) != 0)
     {
       // get mac in string format
       char strmac[REC_ADDR_MAX] = {0};
       memset(strmac, 0, REC_ADDR_MAX);
       print_mac(strmac, mac, maclen);

               my_syslog(LOG_INFO, _("### XDNS - add_xdns_server() for mac [%s]"), strmac);

               // find family type from socket addr
               daemon->ip_type = 4;
               if(l3->sa.sa_family == AF_INET)
               {
                       daemon->ip_type = 4;
               }
#ifdef HAVE_IPV6
               else if(l3->sa.sa_family == AF_INET6)
               {
                       daemon->ip_type = 6;
               }
#endif

                daemon->xdns_forward_list_no=find_mac_tag(strmac);
                if(daemon->xdns_forward_list_no == -1)
                        daemon->xdns_forward_list_no=daemon->xdns_default_list_no;


        my_syslog(LOG_INFO, _("### XDNS- add_xdns_server() for mac [%s] send list tag is:\"%d\""), strmac,daemon->xdns_forward_list_no);


                   // Trigger overriding of upstream server
                   set_option_dnsoverride();
    }
        else
        {
                daemon->xdns_forward_list_no=daemon->xdns_default_list_no;
                reset_option_dnsoverride();
                my_syslog(LOG_INFO, _("#### XDNS : could not find MAC from l3 sockaddr so default fprward list is:\"%d\" !"),daemon->xdns_forward_list_no);
        }

   }
   else
   {
       // find mac from socket addr
   if ((maclen = find_mac(l3, mac, 1, now)) != 0)
   {
       // get mac in string format
       char strmac[REC_ADDR_MAX] = {0};
       memset(strmac, 0, REC_ADDR_MAX);
       print_mac(strmac, mac, maclen);

               my_syslog(LOG_INFO, _("### XDNS - add_xdns_server() for mac [%s]"), strmac);

               // find family type from socket addr
               int iptype = 4;
               if(l3->sa.sa_family == AF_INET)
               {
                       iptype = 4;
               }
#ifdef HAVE_IPV6
               else if(l3->sa.sa_family == AF_INET6)
               {
                       iptype = 6;
               }
#endif

               // get appropriate ipv4 or ipv6 dnsoverride address using mac addr
               union all_addr dnsaddr;
	       union all_addr secondarydnsaddr;
               int primary=0;
               memset(&dnsaddr, 0, sizeof(union all_addr));
               memset(&secondarydnsaddr, 0, sizeof(union all_addr));

               // if xdns addr for same iptype, if not found try for other iptype
               // then try the default.
               if(!find_dnsoverride_server(strmac, &dnsaddr, iptype,0))
               {
                      if(find_dnsoverride_server(strmac, &dnsaddr, (iptype==4)?6:4,0))//try other type
                      {
                             iptype = (iptype==4)?6:4;
                      }
                      else if(!find_dnsoverride_defaultserver(&dnsaddr,&secondarydnsaddr,iptype,&primary))
                      {
                            if(find_dnsoverride_defaultserver(&dnsaddr,&secondarydnsaddr, (iptype==4)?6:4,&primary))//try other type
                            {
                                   iptype = (iptype==4)?6:4;
                            }
                            else
                            {
                                   my_syslog(LOG_INFO, _("#### XDNS : add_xdns_server() Could't find xdns server for [%s] or the default server!"), strmac);
                                   reset_option_dnsoverride();
                                   return plen;
                            }
                      }
               }
               //else found xdns server to use.
		if(primary==2)      // For secondary XDNS server
		{

			struct server *secondserv = NULL;
			char string[64]={0};
               		secondserv = daemon->dns_override_server2;
               		if(!secondserv) // if first time, daemon->dns_override_server2 is NULL. Allocate
               		{
                      		secondserv = whine_malloc(sizeof (struct server)); //allocated once & reused. Not freed.
                      		if(secondserv)
                      		{
                            		memset(secondserv, 0, sizeof(struct server));
                     		}
                      		daemon->dns_override_server2 = secondserv;
              		}

               		if(secondserv)
               		{
                       		if(iptype == 4)
                       		{
                               		my_syslog(LOG_INFO, _("### XDNS - set secondary ipv4 dns_override_server entry in daemon"));
                              		//serv->addr.in.sin_addr = secondarydnsaddr.addr4;
                               		memcpy(&secondserv->addr.in.sin_addr, &secondarydnsaddr.addr4, sizeof(struct in_addr));
                               		secondserv->addr.sa.sa_family = AF_INET;
					inet_ntop(AF_INET, &(secondarydnsaddr.addr4), string, 64);
					my_syslog(LOG_INFO, _("### XDNS - set secondary ipv4 dns_override_server string:%s!"),string);
                     		}
#ifdef HAVE_IPV6
                       		else if(iptype == 6)
                       		{
                               		my_syslog(LOG_INFO, _("### XDNS - set secondary ipv6 dns_override_server entry in daemon"));
                               		//serv->addr.in6.sin6_addr = secondarydnsaddr.addr6;
                               		memcpy(&secondserv->addr.in6.sin6_addr, &secondarydnsaddr.addr6, sizeof(struct in6_addr));
                               		secondserv->addr.sa.sa_family = AF_INET6;
                                        inet_ntop(AF_INET6, &(secondarydnsaddr.addr6), string, 64);
                                        my_syslog(LOG_INFO, _("### XDNS - set secondary ipv6 dns_override_server string:%s!"),string);
                       		}
#endif
               	 		}
   		 	}
			else
			{
				daemon->dns_override_server2=NULL;
				my_syslog(LOG_INFO, _("### XDNS - secondary XDNS server does not exist!"));
			}

	       struct server *serv = NULL;
               serv = daemon->dns_override_server;
               if(!serv) // if first time, daemon->dns_override_server is NULL. Allocate
               {
                      serv = whine_malloc(sizeof (struct server)); //allocated once & reused. Not freed.
                      if(serv)
                      {
                            memset(serv, 0, sizeof(struct server));
                      }
                      daemon->dns_override_server = serv;
               }

               if(serv)
               {
                       if(iptype == 4)
                       {
                               my_syslog(LOG_INFO, _("### XDNS - set ipv4 dns_override_server entry in daemon"));
                              //serv->addr.in.sin_addr = dnsaddr.addr4;
                               memcpy(&serv->addr.in.sin_addr, &dnsaddr.addr4, sizeof(struct in_addr));
                               serv->addr.sa.sa_family = AF_INET;
                       }
#ifdef HAVE_IPV6
                       else if(iptype == 6)
                       {
                               my_syslog(LOG_INFO, _("### XDNS - set ipv6 dns_override_server entry in daemon"));
                               //serv->addr.in6.sin6_addr = dnsaddr.addr6;
                               memcpy(&serv->addr.in6.sin6_addr, &dnsaddr.addr6, sizeof(struct in6_addr));
                               serv->addr.sa.sa_family = AF_INET6;
                       }
#endif
                   // Trigger overriding of upstream server
                   set_option_dnsoverride();
                }
    }
       else
       {
               reset_option_dnsoverride();
	       my_syslog(LOG_INFO, _("#### XDNS : could not find MAC from l3 sockaddr !"));
       }
   }

       return plen;
}

/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */
static size_t add_mac(struct dns_header *header, size_t plen, unsigned char *limit,
		      union mysockaddr *l3, time_t now, int *cacheablep)
{
  my_syslog(LOG_INFO, _("#### XDNS : add_mac() called"));
  int maclen = 0, replace = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
    
  if (option_bool(OPT_ADD_MAC) && (maclen = find_mac(l3, mac, 1, now)) != 0)
    {
      *cacheablep = 0;
      if (option_bool(OPT_STRIP_MAC))
	replace = 1;
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;
  
  if (replace != 0 || maclen != 0)
    plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_MAC, mac, maclen, 0, replace);
  else
  {
	  my_syslog(LOG_INFO, _("#### XDNS : add_mac() maclen = 0 !!"));
	  reset_option_dnsoverride();
  }

  return plen; 
}

struct subnet_opt {
  u16 family;
  u8 source_netmask, scope_netmask; 
  u8 addr[IN6ADDRSZ];
};

static void *get_addrp(union mysockaddr *addr, const short family) 
{
  if (family == AF_INET6)
    return &addr->in6.sin6_addr;

  return &addr->in.sin_addr;
}

static size_t calc_subnet_opt(struct subnet_opt *opt, union mysockaddr *source, int *cacheablep)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int len;
  void *addrp = NULL;
  int sa_family = source->sa.sa_family;
  int cacheable = 0;
  
  opt->source_netmask = 0;
  opt->scope_netmask = 0;
    
  if (source->sa.sa_family == AF_INET6 && daemon->add_subnet6)
    {
      opt->source_netmask = daemon->add_subnet6->mask;
      if (daemon->add_subnet6->addr_used) 
	{
	  sa_family = daemon->add_subnet6->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet6->addr, sa_family);
	  cacheable = 1;
	} 
      else 
	addrp = &source->in6.sin6_addr;
    }

  if (source->sa.sa_family == AF_INET && daemon->add_subnet4)
    {
      opt->source_netmask = daemon->add_subnet4->mask;
      if (daemon->add_subnet4->addr_used)
	{
	  sa_family = daemon->add_subnet4->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet4->addr, sa_family);
	  cacheable = 1; /* Address is constant */
	} 
	else 
	  addrp = &source->in.sin_addr;
    }
  
  opt->family = htons(sa_family == AF_INET6 ? 2 : 1);
  
  if (addrp && opt->source_netmask != 0)
    {
      len = ((opt->source_netmask - 1) >> 3) + 1;
      memcpy(opt->addr, addrp, len);
      if (opt->source_netmask & 7)
	opt->addr[len-1] &= 0xff << (8 - (opt->source_netmask & 7));
    }
  else
    {
      cacheable = 1; /* No address ever supplied. */
      len = 0;
    }

  if (cacheablep)
    *cacheablep = cacheable;
  
  return len + 4;
}
 
/* OPT_CLIENT_SUBNET = client subnet is added
   OPT_CLIENT_SUBNET + OPT_STRIP_ECS = client subnet is replaced
   OPT_STRIP_ECS = client subnet is removed */
static size_t add_source_addr(struct dns_header *header, size_t plen, unsigned char *limit,
			      union mysockaddr *source, int *cacheable)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int replace = 0, len = 0;
  struct subnet_opt opt;
  
  if (option_bool(OPT_CLIENT_SUBNET))
    {
      if (option_bool(OPT_STRIP_ECS))
	replace = 1;
      len = calc_subnet_opt(&opt, source, cacheable);
    }
  else if (option_bool(OPT_STRIP_ECS))
    replace = 2;
  else
    return plen;

  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, EDNS0_OPTION_CLIENT_SUBNET, (unsigned char *)&opt, len, 0, replace);
}

int check_source(struct dns_header *header, size_t plen, unsigned char *pseudoheader, union mysockaddr *peer)
{
  /* Section 9.2, Check that subnet option in reply matches. */
  
  int len, calc_len;
  struct subnet_opt opt;
  unsigned char *p;
  int code, i, rdlen;
  
  calc_len = calc_subnet_opt(&opt, peer, NULL);
   
  if (!(p = skip_name(pseudoheader, header, plen, 10)))
    return 1;
  
  p += 8; /* skip UDP length and RCODE */
  
  GETSHORT(rdlen, p);
  if (!CHECK_LEN(header, p, plen, rdlen))
    return 1; /* bad packet */
  
  /* check if option there */
   for (i = 0; i + 4 < rdlen; i += len + 4)
     {
       GETSHORT(code, p);
       GETSHORT(len, p);
       if (code == EDNS0_OPTION_CLIENT_SUBNET)
	 {
	   /* make sure this doesn't mismatch. */
	   opt.scope_netmask = p[3];
	   if (len != calc_len || memcmp(p, &opt, len) != 0)
	     return 0;
	 }
       p += len;
     }
   
   return 1;
}

/* See https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic for
 * detailed information on packet formating.
 */
#define UMBRELLA_VERSION    1
#define UMBRELLA_TYPESZ     2

#define UMBRELLA_ASSET      0x0004
#define UMBRELLA_ASSETSZ    sizeof(daemon->umbrella_asset)
#define UMBRELLA_ORG        0x0008
#define UMBRELLA_ORGSZ      sizeof(daemon->umbrella_org)
#define UMBRELLA_IPV4       0x0010
#define UMBRELLA_IPV6       0x0020
#define UMBRELLA_DEVICE     0x0040
#define UMBRELLA_DEVICESZ   sizeof(daemon->umbrella_device)

struct umbrella_opt {
  u8 magic[4];
  u8 version;
  u8 flags;
  /* We have 4 possible fields since we'll never send both IPv4 and
   * IPv6, so using the larger of the two to calculate max buffer size.
   * Each field also has a type header.  So the following accounts for
   * the type headers and each field size to get a max buffer size.
   */
  u8 fields[4 * UMBRELLA_TYPESZ + UMBRELLA_ORGSZ + IN6ADDRSZ + UMBRELLA_DEVICESZ + UMBRELLA_ASSETSZ];
};

static size_t add_umbrella_opt(struct dns_header *header, size_t plen, unsigned char *limit, union mysockaddr *source, int *cacheable)
{
  *cacheable = 0;

  struct umbrella_opt opt = {{"ODNS"}, UMBRELLA_VERSION, 0, {}};
  u8 *u = &opt.fields[0];
  int family = source->sa.sa_family;
  int size = family == AF_INET ? INADDRSZ : IN6ADDRSZ;

  if (daemon->umbrella_org)
    {
      PUTSHORT(UMBRELLA_ORG, u);
      PUTLONG(daemon->umbrella_org, u);
    }
  
  PUTSHORT(family == AF_INET ? UMBRELLA_IPV4 : UMBRELLA_IPV6, u);
  memcpy(u, get_addrp(source, family), size);
  u += size;
  
  if (option_bool(OPT_UMBRELLA_DEVID))
    {
      PUTSHORT(UMBRELLA_DEVICE, u);
      memcpy(u, (char *)&daemon->umbrella_device, UMBRELLA_DEVICESZ);
      u += UMBRELLA_DEVICESZ;
    }

  if (daemon->umbrella_asset)
    {
      PUTSHORT(UMBRELLA_ASSET, u);
      PUTLONG(daemon->umbrella_asset, u);
    }
  
  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, EDNS0_OPTION_UMBRELLA, (unsigned char *)&opt, u - (u8 *)&opt, 0, 1);
}

/* Set *check_subnet if we add a client subnet option, which needs to checked 
   in the reply. Set *cacheable to zero if we add an option which the answer
   may depend on. */
size_t add_edns0_config(struct dns_header *header, size_t plen, unsigned char *limit, 
			union mysockaddr *source, time_t now, int *cacheable)    
{
  *cacheable = 1;
  
  plen  = add_mac(header, plen, limit, source, now, cacheable);
  plen = add_dns_client(header, plen, limit, source, now, cacheable);
  
  /* <XDNS> */
  plen = add_xdns_server(header, plen, limit, source, now);

  //if (daemon->dns_client_id)
   // plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_NOMCPEID, 
     //			    (unsigned char *)daemon->dns_client_id, strlen(daemon->dns_client_id), 0, 1);

  plen = add_cpe_tag(header, plen, limit, source, now);
  /* </XDNS> */

  if (option_bool(OPT_UMBRELLA))
    plen = add_umbrella_opt(header, plen, limit, source, cacheable);
  
  plen = add_source_addr(header, plen, limit, source, cacheable);
  	  
  return plen;
}
