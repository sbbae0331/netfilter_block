#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

uint8_t *hostname;
uint8_t *HTTP_METHOD[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

uint32_t filter_host(unsigned char* buf, int size) {

	uint8_t *ptr;
	// IP Header: TCP Check / src ip / dst ip (TCP (6))
	uint8_t *ip_ptr = ptr = buf;
	int ip_header_len = (*(ip_ptr) & 0b00001111) * 4;
	int ip_total_len = *(ip_ptr+2) * 256 + *(ip_ptr+3);
	// TCP Check (TCP (6))
	if (*(ptr+=9) == 0x06) {
		printf("\nProtocol: TCP\n");
		// src ip
		ptr += 3;
		printf("Source IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
		// dst ip
		printf("Destination IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
	}
	else return 0;

	// TCP Header: src port / dst port / Payload check (TCP Segment Len)
	uint8_t *tcp_ptr = ptr = ip_ptr + ip_header_len;
	int tcp_header_len = (*(ptr + 12) >> 4) * 4;
	// src port
	printf("Source Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// dst port
	printf("Destination Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// Payload check (TCP Segment Len)
	// TCP Payload Segment Size = IP total length - IP header length - TCP header len
 	int tcp_seg_size = ip_total_len - ip_header_len - tcp_header_len;
	printf("TCP Payload Segment Size: %d\n", tcp_seg_size);

	// Payload hexa decimal value (32 bytes)
	uint8_t *payload_ptr = tcp_ptr + tcp_header_len;
	if (tcp_seg_size) {
		ptr = strtok(payload_ptr, "\r\n");
		if (ptr != NULL) {
			int i = 0;
			int http_request_flag = 0;
			for (; i < 6; i++) {
				if(!strncmp(ptr, HTTP_METHOD[i], strlen(HTTP_METHOD[i]))) {
					http_request_flag = 1;
					break;
				}
			}
			if (http_request_flag) printf("HTTP Method: %s\n", HTTP_METHOD[i]);
			else return 0;

			ptr = strtok(NULL, "\r\n");
			if (ptr != NULL) {
				ptr = strtok(ptr, ": ");
				uint8_t *http_host = strtok(NULL, ": ");
				printf("HTTP Host: %s\n", http_host);

				// filtering packet by hostname
				if(!strncmp(http_host, hostname, strlen(hostname))) {
					return 1;
				}
			}
		}
	}
	return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	uint32_t flag = filter_host(data, ret);

	fputc('\n', stdout);

	if (flag) return 0;
	else return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (id) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		printf("syntax: netfilter_block <host>\n");
		printf("sample: netfilter_block test.gilgil.net\n");
		return -1;
	}

	hostname = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

