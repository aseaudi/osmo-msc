#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

struct gsm_network;
struct gsm_sms_queue;
struct vty;

struct sms_queue_config {
	char *db_file_path;			/* SMS database file path */
	int max_fail;				/* maximum number of delivery failures */
	int max_pending;			/* maximum number of gsm_sms_pending in RAM */
};

struct sms_queue_config *sms_queue_cfg_alloc(void *ctx);

#define VSUB_USE_SMS_PENDING "SMS-pending"
#define MSC_A_USE_SMS_PENDING "SMS-pending"

int sms_queue_start(struct gsm_network *net);
int sms_queue_trigger(struct gsm_sms_queue *);

/* vty helper functions */
int sms_queue_stats(struct gsm_sms_queue *, struct vty* vty);
int sms_queue_set_max_pending(struct gsm_sms_queue *, int max);
int sms_queue_set_max_failure(struct gsm_sms_queue *, int fail);
int sms_queue_clear(struct gsm_sms_queue *);
int sms_queue_sms_is_pending(struct gsm_sms_queue *smsq, unsigned long long sms_id);

#endif
