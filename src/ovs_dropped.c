/**
 * collectd - src/ovs_dropped.c
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 *of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to
 *do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 *all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Volodymyr Mytnyk <volodymyrx.mytnyk@intel.com>
 **/
#include<time.h>

#include "collectd.h"

#include "common.h" /* auxiliary functions */

#include "utils_ovs.h" /* OVS helpers */

#define OVS_EVENTS_IFACE_NAME_SIZE 128
#define OVS_EVENTS_IFACE_UUID_SIZE 64
#define OVS_EVENTS_EXT_IFACE_ID_SIZE 64
#define OVS_EVENTS_EXT_VM_UUID_SIZE 64
#define OVS_EVENTS_PLUGIN "ovs_dropped"
#define OVS_EVENTS_CTX_LOCK                                                    \
  for (int __i = ovs_events_ctx_lock(); __i != 0; __i = ovs_events_ctx_unlock())

/* Link status type */
enum ovs_events_link_status_e { UP, DOWN };
typedef enum ovs_events_link_status_e ovs_events_link_status_t;

/* Link speed type */
typedef unsigned long ovs_events_link_speed_t;

/* Link duplex type */
enum ovs_events_link_duplex_e { FULL, HALF, UNKNOWN };
typedef enum ovs_events_link_duplex_e ovs_events_link_duplex_t;

/* Link link drop type */
typedef unsigned long ovs_events_tx_drop_t;
typedef unsigned long ovs_events_rx_drop_t;
typedef unsigned long ovs_dropped_config_t;

/* Interface info */
struct ovs_events_iface_info_s {
  char name[OVS_EVENTS_IFACE_NAME_SIZE];           /* interface name */
  char uuid[OVS_EVENTS_IFACE_UUID_SIZE];           /* interface UUID */
  char ext_iface_id[OVS_EVENTS_EXT_IFACE_ID_SIZE]; /* external interface id */
  char ext_vm_uuid[OVS_EVENTS_EXT_VM_UUID_SIZE];   /* external VM UUID */
  ovs_events_link_status_t link_status;            /* interface link status */
  ovs_events_tx_drop_t tx_drop;              /* interface tx dropped */
  ovs_events_rx_drop_t rx_drop;              /* interface rx dropped */
  ovs_events_rx_drop_t within_flag;              /* interface within flag, 'alarm' -> 'OK'*/
  ovs_dropped_config_t dropped_threshold;
  struct ovs_events_iface_info_s *next;            /* next interface info */
};
typedef struct ovs_events_iface_info_s ovs_events_iface_info_t;

/* Interface list */
struct ovs_events_iface_list_s {
  char name[OVS_EVENTS_IFACE_NAME_SIZE]; /* interface name */
  struct ovs_events_iface_list_s *next;  /* next interface info */
};
typedef struct ovs_events_iface_list_s ovs_events_iface_list_t;

/* event type.*/
enum ovs_event_type_e {
  LINK_STATE = 1ul << 0,
  LINK_DROP = 1ul << 1
};
typedef enum ovs_event_type_e ovs_event_type_t;

/* OVS events configuration data */
struct ovs_events_config_s {
  _Bool send_notification;                 /* sent notification to collectd? */
  char ovs_db_node[OVS_DB_ADDR_NODE_SIZE]; /* OVS DB node */
  char ovs_db_serv[OVS_DB_ADDR_SERVICE_SIZE]; /* OVS DB service */
  char ovs_db_unix[OVS_DB_ADDR_UNIX_SIZE];    /* OVS DB unix socket path */
  ovs_event_type_t event_type;                /* OVS event type */
  ovs_dropped_config_t config_threshold;
  int config_debug;
  ovs_events_iface_list_t *ifaces;            /* interface info */
};
typedef struct ovs_events_config_s ovs_events_config_t;

/* OVS events context type */
struct ovs_events_ctx_s {
  pthread_mutex_t mutex;      /* mutex to lock the context */
  ovs_db_t *ovs_db;           /* pointer to OVS DB instance */
  ovs_events_config_t config; /* plugin config */
  char *ovs_db_select_params; /* OVS DB select parameter request */
  _Bool is_db_available;      /* specify whether OVS DB is available */
};
typedef struct ovs_events_ctx_s ovs_events_ctx_t;


typedef struct list_head {
	struct list_head *next, *prev;
}list_t_drop;

struct ovs_dropped_laststatus_cache{
  list_t_drop next;
  char *iface_name;
  int status;
  u_int32_t cur_time;
};

#define OVS_DROP_INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (void *) 0;
	entry->prev = (void *) 0;
}

#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

static pthread_mutex_t drop_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ovs_drop_cache_lock() {
  pthread_mutex_lock(&drop_cache_mutex);
  return 1;
}

static int ovs_drop_cache_unlock() {
  pthread_mutex_unlock(&drop_cache_mutex);
  return 0;
}

static list_t_drop drop_head;

static inline void * ovs_dropped_laststatus_cache_lookup(char *iface_name) {
    struct ovs_dropped_laststatus_cache *pos = NULL, *temp = NULL;
    ovs_drop_cache_lock();
    list_for_each_entry_safe(pos, temp, &drop_head, next)
    {
            if(!(strncmp(pos->iface_name, iface_name,  strlen(iface_name)))){
                ovs_drop_cache_unlock();
                return pos;
            }
    }
    ovs_drop_cache_unlock();
    return NULL;
}

static inline int ovs_dropped_laststatus_cache_add(struct ovs_dropped_laststatus_cache *new) {
  ovs_drop_cache_lock();
  list_add_tail(&(new->next), &drop_head);
  ovs_drop_cache_unlock();
  return 0;
}

static inline int ovs_dropped_laststatus_cache_del(char *iface_name) {
    struct ovs_dropped_laststatus_cache *pos = NULL, *temp = NULL;
    ovs_drop_cache_lock();
    list_for_each_entry_safe(pos, temp, &drop_head, next)
    {
            if(!(strncmp(pos->iface_name, iface_name,  strlen(iface_name)))){
                    list_del(&(pos->next));
                    ovs_drop_cache_unlock();
                    sfree(pos->iface_name);
                    sfree(pos);
                    pos = NULL;
                    return 0;
            }
    }
    ovs_drop_cache_unlock();
    return 1;
}

static inline int ovs_dropped_laststatus_cache_free() {
    struct ovs_dropped_laststatus_cache *pos = NULL, *temp = NULL;
    ovs_drop_cache_lock();
    list_for_each_entry_safe(pos, temp, &drop_head, next)
    {
        list_del(&(pos->next));
        sfree(pos->iface_name);
        sfree(pos);
        pos = NULL;
        
    }
    ovs_drop_cache_unlock();
    return 0;
}

static void ovs_dropped_timeout_cache_sendnotification(const ovs_events_iface_info_t *ifinfo,
        struct ovs_dropped_laststatus_cache *pos);

static inline int ovs_dropped_laststatus_cache_timeout_free(ovs_events_iface_info_t *ifinfo) {
    struct ovs_dropped_laststatus_cache *pos = NULL, *temp = NULL;
    u_int32_t cur_time = time(NULL);
    ovs_drop_cache_lock();
    list_for_each_entry_safe(pos, temp, &drop_head, next)
    {
	//WARNING(OVS_EVENTS_PLUGIN "%d, %d\n", cur_time , pos->cur_time);
        if((cur_time - pos->cur_time) > 11){
            list_del(&(pos->next));

            if (!(strstr(pos->iface_name, "br-"))) {
		if(pos->status == 1)
            	  ovs_dropped_timeout_cache_sendnotification(ifinfo, pos);
            }

            sfree(pos->iface_name);
            sfree(pos);
            pos = NULL;
        }
        
    }
    ovs_drop_cache_unlock();
    return 0;
}


/* utils of ovs event notify chain.*/
typedef void (*ovs_event_notifier_fn_t)(const ovs_events_iface_info_t *);

struct ovs_event_notifier_block {
  ovs_event_notifier_fn_t action;
  struct ovs_event_notifier_block *next;
};

struct ovs_event_notifier_head {
  struct ovs_event_notifier_block *head;
};

#define OVS_EVENT_NOTIFIER_INIT(name) { \
        (name).head = NULL; }

#define OVS_EVENT_NOTIFIER_HEAD(name)   \
  struct ovs_event_notifier_head name = { \
        .head = NULL}

static OVS_EVENT_NOTIFIER_HEAD(ovs_event_chain);

static inline void ovs_event_notifier_call(const void *val) {
  struct ovs_event_notifier_block *nb = ovs_event_chain.head;
  while (nb) { nb->action(val); nb = nb->next; }
}

static inline int ovs_event_notifier_register(
  struct ovs_event_notifier_block *new) {
  struct ovs_event_notifier_block *nb = ovs_event_chain.head;
  new->next = nb;
  ovs_event_chain.head = new;
  return 0;
}


/* ovs event actions forward declaration */
//static void ovs_event_link_state_action(const ovs_events_iface_info_t *);
//static void ovs_event_link_speed_action(const ovs_events_iface_info_t *);
static void ovs_event_rxtx_drop_action(const ovs_events_iface_info_t *);

//static struct ovs_event_notifier_block link_state_nb =
//  { .action = ovs_event_link_state_action, };
//static struct ovs_event_notifier_block link_speed_nb =
//  { .action = ovs_event_link_speed_action, };
static struct ovs_event_notifier_block rxtx_drop_nb =
  { .action = ovs_event_rxtx_drop_action, };

static int ovs_event_notifier_register_once = 0;

/*
 * Private variables
 */
static ovs_events_ctx_t ovs_events_ctx = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .config = {.send_notification = 1,     /* send notification by default */
               .ovs_db_node = "localhost", /* use default OVS DB node */
               .ovs_db_serv = "6640",      /* use default OVS DB service */
               .config_debug = 0,
               .event_type = LINK_STATE}   /* use default OVS event type. */
};


/* This function is used only by "OVS_EVENTS_CTX_LOCK" define (see above).
 * It always returns 1 when context is locked.
 */
static int ovs_events_ctx_lock() {
  pthread_mutex_lock(&ovs_events_ctx.mutex);
  return 1;
}

/* This function is used only by "OVS_EVENTS_CTX_LOCK" define (see above).
 * It always returns 0 when context is unlocked.
 */
static int ovs_events_ctx_unlock() {
  pthread_mutex_unlock(&ovs_events_ctx.mutex);
  return 0;
}


/* Check if given interface name exists in configuration file. It
 * returns 1 if exists otherwise 0. If no interfaces are configured,
 * -1 is returned
 */
static int ovs_events_config_iface_exists(const char *ifname) {
  if (ovs_events_ctx.config.ifaces == NULL)
    return -1;

  if (strstr(ifname, "br-")) {
    ERROR(OVS_EVENTS_PLUGIN ": interface's name has prefix br-, ignor it");
    return 0;
  }

  /* check if given interface exists */
  for (ovs_events_iface_list_t *iface = ovs_events_ctx.config.ifaces; iface;
       iface = iface->next)
    if (strcmp(ifname, iface->name) == 0)
      return 1;

  return 0;
}

/* Get OVS DB select parameter request based on rfc7047,
 * "Transact" & "Select" section
 */
static char *ovs_events_get_select_params() {
  size_t buff_size = 0;
  size_t buff_off = 0;
  char *opt_buff = NULL;
  static const char params_fmt[] = "[\"Open_vSwitch\"%s]";
  static const char option_fmt[] =
      ",{\"op\":\"select\",\"table\":\"Interface\","
      "\"where\":[[\"name\",\"==\",\"%s\"]],"
      "\"columns\":[\"name\",\"_uuid\",\"external_ids\", \"statistics\"]}";
  static const char default_opt[] =
      ",{\"op\":\"select\",\"table\":\"Interface\","
      "\"where\":[],\"columns\":[\"name\",\"_uuid\",\"external_ids\", \"statistics\"]}";
  /* setup OVS DB interface condition */
  for (ovs_events_iface_list_t *iface = ovs_events_ctx.config.ifaces; iface;
       iface = iface->next) {
    /* allocate new buffer (format size + ifname len is good enough) */
    buff_size += sizeof(option_fmt) + strlen(iface->name);
    char *new_buff = realloc(opt_buff, buff_size);
    if (new_buff == NULL) {
      sfree(opt_buff);
      return NULL;
    }
    opt_buff = new_buff;
    int ret = snprintf(opt_buff + buff_off, buff_size - buff_off, option_fmt,
                       iface->name);
    if (ret < 0) {
      sfree(opt_buff);
      return NULL;
    }
    buff_off += ret;
  }
  /* if no interfaces are configured, use default params */
  if (opt_buff == NULL)
    if ((opt_buff = strdup(default_opt)) == NULL)
      return NULL;

  /* allocate memory for OVS DB select params */
  size_t params_size = sizeof(params_fmt) + strlen(opt_buff);
  char *params_buff = calloc(1, params_size);
  if (params_buff == NULL) {
    sfree(opt_buff);
    return NULL;
  }

  /* create OVS DB select params */
  if (snprintf(params_buff, params_size, params_fmt, opt_buff) < 0)
    sfree(params_buff);

  sfree(opt_buff);
  return params_buff;
}

/* Release memory allocated for configuration data */
static void ovs_events_config_free() {
  ovs_events_iface_list_t *del_iface = NULL;
  sfree(ovs_events_ctx.ovs_db_select_params);
  while (ovs_events_ctx.config.ifaces) {
    del_iface = ovs_events_ctx.config.ifaces;
    ovs_events_ctx.config.ifaces = ovs_events_ctx.config.ifaces->next;
    sfree(del_iface);
  }
}

/* Parse/process "Interfaces" configuration option. Returns 0 if success
 * otherwise -1 (error)
 */
static int ovs_events_config_get_interfaces(const oconfig_item_t *ci) {
  for (int j = 0; j < ci->values_num; j++) {
    /* check interface name type */
    if (ci->values[j].type != OCONFIG_TYPE_STRING) {
      ERROR(OVS_EVENTS_PLUGIN ": given interface name is not a string [idx=%d]",
            j);
      return -1;
    }
    /* allocate memory for configured interface */
    ovs_events_iface_list_t *new_iface = calloc(1, sizeof(*new_iface));
    if (new_iface == NULL) {
      ERROR(OVS_EVENTS_PLUGIN ": calloc () copy interface name fail");
      return -1;
    } else {
      /* store interface name */
      sstrncpy(new_iface->name, ci->values[j].value.string,
               sizeof(new_iface->name));
      new_iface->next = ovs_events_ctx.config.ifaces;
      ovs_events_ctx.config.ifaces = new_iface;
      DEBUG(OVS_EVENTS_PLUGIN ": found monitored interface \"%s\"",
            new_iface->name);
    }
  }
  return 0;
}

static int ovs_events_config_get_dropped_threshold(const oconfig_item_t *ci) {
  /* reset the default event type since specified type is given */
  ovs_events_ctx.config.config_threshold = 0;
  int status = 0;
  int threshold = 0;

  //status = cf_util_get_int(child, &buffer_size);

  status = cf_util_get_int(ci, &threshold);
  if (!status) {
      ovs_events_ctx.config.config_threshold = threshold;
      DEBUG(OVS_EVENTS_PLUGIN ": found droppedd threshold\"%ld\"", threshold);
  } else {
      ERROR(OVS_EVENTS_PLUGIN ": invalid threshold");
      return (-1);
  }
  
  return (0);
}



/* Parse/process "EventType" configuration option. Returns 0 if success
 * otherwise -1 (error)
 */
static int ovs_events_config_get_event_type(const oconfig_item_t *ci) {
  /* reset the default event type since specified type is given */
  ovs_events_ctx.config.event_type = 0;
  for (int j = 0; j < ci->values_num; j++) {
    /* check EventType type */
    if (ci->values[j].type != OCONFIG_TYPE_STRING) {
      ERROR(OVS_EVENTS_PLUGIN
            ": given event type is not a string [idx=%d]", j);
      return (-1);
    }

    if (!strcmp(ci->values[j].value.string, "link_dropped")) {
      ovs_events_ctx.config.event_type |= LINK_DROP;
      DEBUG(OVS_EVENTS_PLUGIN ": found event type \"%s\"",
            "link_state");
    } else {
      ERROR(OVS_EVENTS_PLUGIN ": invalid event type");
      return (-1);
    }
  }
  return (0);
}

/* Parse plugin configuration file and store the config
 * in allocated memory. Returns negative value in case of error.
 */
static int ovs_events_plugin_config(oconfig_item_t *ci) {
  _Bool dispatch_values = 0;
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("SendNotification", child->key) == 0) {
      if (cf_util_get_boolean(child,
                              &ovs_events_ctx.config.send_notification) != 0) {
        ovs_events_config_free();
        return -1;
      }
    } else if (strcasecmp("Address", child->key) == 0) {
      if (cf_util_get_string_buffer(
              child, ovs_events_ctx.config.ovs_db_node,
              sizeof(ovs_events_ctx.config.ovs_db_node)) != 0) {
        ovs_events_config_free();
        return -1;
      }
    } else if (strcasecmp("Port", child->key) == 0) {
      char *service = NULL;
      if (cf_util_get_service(child, &service) != 0) {
        ovs_events_config_free();
        return -1;
      }
      strncpy(ovs_events_ctx.config.ovs_db_serv, service,
              sizeof(ovs_events_ctx.config.ovs_db_serv));
      sfree(service);
    } else if (strcasecmp("Socket", child->key) == 0) {
      if (cf_util_get_string_buffer(
              child, ovs_events_ctx.config.ovs_db_unix,
              sizeof(ovs_events_ctx.config.ovs_db_unix)) != 0) {
        ovs_events_config_free();
        return -1;
      }
    } else if (strcasecmp("Interfaces", child->key) == 0) {
      if (ovs_events_config_get_interfaces(child) != 0) {
        ovs_events_config_free();
        return -1;
      }
    } else if (strcasecmp("DispatchValues", child->key) == 0) {
      if (cf_util_get_boolean(child, &dispatch_values) != 0) {
        ovs_events_config_free();
        return -1;
      }
    } else if (strcasecmp("EventType", child->key) == 0) {
      if (ovs_events_config_get_event_type(child) != 0) {
        ovs_events_config_free();
        return (-1);
      }
    } else if (strcasecmp("DroppedThreshold", child->key) == 0) {
      if (ovs_events_config_get_dropped_threshold(child) != 0) {
        ovs_events_config_free();
        return (-1);
      }
    } else if (strcasecmp("Debug", child->key) == 0) {
      if (cf_util_get_int(child, &(ovs_events_ctx.config.config_debug)) != 0) {
        ovs_events_config_free();
        return (-1);
      }
    } else {
      ERROR(OVS_EVENTS_PLUGIN ": option '%s' is not allowed here", child->key);
      ovs_events_config_free();
      return -1;
    }
  }
  /* Check and warn about invalid configuration */
  if (!ovs_events_ctx.config.send_notification && !dispatch_values) {
    WARNING(OVS_EVENTS_PLUGIN
            ": send notification and dispatch values "
            "options are disabled. No information will be dispatched by the "
            "plugin. Please check your configuration");
  }

  return 0;
}

/* Dispatch OVS interface link status event to collectd */
static void ovs_events_dispatch_notification(const ovs_events_iface_info_t *ifinfo) {
  ovs_event_notifier_call(ifinfo);
}

static void ovs_dropped_timeout_cache_sendnotification(const ovs_events_iface_info_t *ifinfo, 
        struct ovs_dropped_laststatus_cache *pos){
  const char *msg_link_dropped = NULL;
  const char *msg_link_type = "link_dropped";
  notification_t n = {
      NOTIF_FAILURE, cdtime(), "", "", OVS_EVENTS_PLUGIN, "", "", "", NULL};
    
  msg_link_dropped = "Forwarding exceeding within threshold";

  n.severity = NOTIF_WARNING;

  /* add interface metadata to the notification */
  if (plugin_notification_meta_add_string(&n, "uuid", ifinfo->uuid) < 0) {
    ERROR(OVS_EVENTS_PLUGIN ": add interface uuid meta data failed");
    return;
  }

  if (strlen(ifinfo->ext_vm_uuid) > 0) {
    if (plugin_notification_meta_add_string(&n, "vm-uuid",
                                            ifinfo->ext_vm_uuid) < 0) {
      ERROR(OVS_EVENTS_PLUGIN ": add interface vm-uuid meta data failed");
      return;
    }
  }

  if (strlen(ifinfo->ext_iface_id) > 0) {
    if (plugin_notification_meta_add_string(&n, "iface-id",
                                            ifinfo->ext_iface_id) < 0) {
      ERROR(OVS_EVENTS_PLUGIN ": add interface iface-id meta data failed");
      return;
    }
  }

  /* fill the notification data */
  snprintf(n.message, sizeof(n.message),
           "link dropped of \"%s\" interface has been changed to \"%s\"",
           ifinfo->name, msg_link_dropped);
  sstrncpy(n.host, hostname_g, sizeof(n.host));
  sstrncpy(n.plugin_instance, pos->iface_name, sizeof(n.plugin_instance));
  sstrncpy(n.type, "gauge", sizeof(n.type));
  sstrncpy(n.type_instance, msg_link_type, sizeof(n.type_instance));
  plugin_dispatch_notification(&n);

}



static void ovs_event_rxtx_drop_action(const ovs_events_iface_info_t *ifinfo){
  const char *msg_link_dropped = NULL;
  const char *msg_link_type = "link_dropped";
  notification_t n = {
      NOTIF_FAILURE, cdtime(), "", "", OVS_EVENTS_PLUGIN, "", "", "", NULL};
    
  if(!ifinfo->rx_drop && !ifinfo->tx_drop && !ifinfo->within_flag)
      return;

  msg_link_dropped = "Forwarding exceeding above threshold";

  if(ifinfo->rx_drop && ifinfo->tx_drop)
      msg_link_type="link_txrx_dropped";
  else if(ifinfo->tx_drop)
      msg_link_type="link_tx_dropped";
  else if(ifinfo->rx_drop)
      msg_link_type="link_rx_dropped";
  else if(ifinfo->within_flag)
    msg_link_dropped = "Forwarding exceeding within threshold";

  n.severity = NOTIF_WARNING;

  /* add interface metadata to the notification */
  if (plugin_notification_meta_add_string(&n, "uuid", ifinfo->uuid) < 0) {
    ERROR(OVS_EVENTS_PLUGIN ": add interface uuid meta data failed");
    return;
  }

  if (strlen(ifinfo->ext_vm_uuid) > 0) {
    if (plugin_notification_meta_add_string(&n, "vm-uuid",
                                            ifinfo->ext_vm_uuid) < 0) {
      ERROR(OVS_EVENTS_PLUGIN ": add interface vm-uuid meta data failed");
      return;
    }
  }

  if (strlen(ifinfo->ext_iface_id) > 0) {
    if (plugin_notification_meta_add_string(&n, "iface-id",
                                            ifinfo->ext_iface_id) < 0) {
      ERROR(OVS_EVENTS_PLUGIN ": add interface iface-id meta data failed");
      return;
    }
  }

  /* fill the notification data */
  snprintf(n.message, sizeof(n.message),
           "link dropped of \"%s\" interface has been changed to \"%s\"",
           ifinfo->name, msg_link_dropped);
  sstrncpy(n.host, hostname_g, sizeof(n.host));
  sstrncpy(n.plugin_instance, ifinfo->name, sizeof(n.plugin_instance));
  sstrncpy(n.type, "gauge", sizeof(n.type));
  sstrncpy(n.type_instance, msg_link_type, sizeof(n.type_instance));
  plugin_dispatch_notification(&n);

}


/* Dispatch OVS DB terminate connection event to collectd */
static void ovs_events_dispatch_terminate_notification(const char *msg) {
  notification_t n = {
      NOTIF_FAILURE, cdtime(), "", "", OVS_EVENTS_PLUGIN, "", "", "", NULL};
  sstrncpy(n.message, msg, sizeof(n.message));
  sstrncpy(n.host, hostname_g, sizeof(n.host));
  plugin_dispatch_notification(&n);
}

static int ovs_dropped_get_statistics_info(yajl_val jobject_old, yajl_val jobject_new, 
                                        ovs_events_iface_info_t *ifinfo){
  yajl_val joldvalue = NULL;
  yajl_val jnewvalue = NULL;
  yajl_val old_statistic = NULL;
  yajl_val new_statistic = NULL;
  yajl_val old_stat = NULL;
  yajl_val new_stat = NULL;
  char *old_key = NULL, *new_key = NULL;
  int64_t old_value = 0, new_value = 0, rx_dropped_counter = 0, tx_dropped_counter = 0;
  int have_dropped_field = 0;

  /* get OVS DB interface link dropped*/
  joldvalue = ovs_utils_get_value_by_key(jobject_old, "statistics");
  if (joldvalue == NULL && !YAJL_IS_ARRAY(joldvalue)) {
    ERROR(OVS_EVENTS_PLUGIN ": statistics old info error, is Null\n");
    return -1;
  }

  jnewvalue = ovs_utils_get_value_by_key(jobject_new, "statistics");
  if (jnewvalue != NULL && YAJL_IS_ARRAY(jnewvalue)) {
    new_statistic = YAJL_GET_ARRAY(jnewvalue)->values[1];
    old_statistic = YAJL_GET_ARRAY(joldvalue)->values[1];
    //WARNING(OVS_EVENTS_PLUGIN ": rxtx_dropped:%s, len:%ld, value:%s\n", 
      //              "inin1", YAJL_GET_ARRAY(new_statistic)->len, YAJL_GET_STRING(new_statistic));
     
    for (size_t i = 0; i < YAJL_GET_ARRAY(new_statistic)->len; i++) {
	new_key = NULL; 
	old_key = NULL;
	if(YAJL_GET_ARRAY(old_statistic)->values && YAJL_GET_ARRAY(new_statistic)->values){
	    new_stat = YAJL_GET_ARRAY(new_statistic)->values[i];
	    old_stat = YAJL_GET_ARRAY(old_statistic)->values[i];
	    new_key = YAJL_GET_STRING(YAJL_GET_ARRAY(new_stat)->values[0]);
	    old_key = YAJL_GET_STRING(YAJL_GET_ARRAY(old_stat)->values[0]);

	    new_value = YAJL_GET_INTEGER(YAJL_GET_ARRAY(new_stat)->values[1]);
	    old_value = YAJL_GET_INTEGER(YAJL_GET_ARRAY(old_stat)->values[1]);
	}

        if(old_key && new_key){
            //WARNING(OVS_EVENTS_PLUGIN " info  %ld, name:%s, newkey:%s, newvalue:%ld, oldkey:%s, oldvalue:%ld\n", i, ifinfo->name, new_key, new_value, old_key, old_value ); 
            if((!strncmp(new_key, "rx_dropped", strlen("rx_dropped"))) && 
                    (!strncmp(old_key, "rx_dropped", strlen("rx_dropped")))){
                have_dropped_field = 1;
                //WARNING(OVS_EVENTS_PLUGIN " rx_drop %ld, name:%s, newkey:%s, newvalue:%ld, oldkey:%s, oldvalue:%ld\n", i, ifinfo->name, new_key, new_value, old_key, old_value ); 
                rx_dropped_counter = new_value - old_value;
                if(rx_dropped_counter >= ovs_events_ctx.config.config_threshold){
                    ifinfo->rx_drop = rx_dropped_counter; 
                }
                else
                    ifinfo->rx_drop = 0; 
            }

            if((!strncmp(new_key, "tx_dropped", strlen("tx_dropped"))) && 
                    (!strncmp(old_key, "tx_dropped", strlen("tx_dropped")))){
                have_dropped_field = 1;
                //WARNING(OVS_EVENTS_PLUGIN " tx_drop %ld, name:%s, newkey:%s, newvalue:%ld, oldkey:%s, oldvalue:%ld\n", i, ifinfo->name, new_key, new_value, old_key, old_value ); 
                tx_dropped_counter = new_value - old_value;
                if(tx_dropped_counter >= ovs_events_ctx.config.config_threshold){
                    ifinfo->tx_drop = tx_dropped_counter; 
                }
                else
                    ifinfo->tx_drop = 0; 
            }

        }
    }

  }
  else{
    ERROR(OVS_EVENTS_PLUGIN ": statistics new info error, is Null\n");
    return -1;
  }

  if(ifinfo->rx_drop || ifinfo->tx_drop){
      char *name = ifinfo->name;
      struct ovs_dropped_laststatus_cache * node = ovs_dropped_laststatus_cache_lookup(name);
      if(!node){
          struct ovs_dropped_laststatus_cache *new = (struct ovs_dropped_laststatus_cache*)malloc(
                      sizeof(struct ovs_dropped_laststatus_cache));
          new->iface_name = (char*)malloc(strlen(ifinfo->name)+1);
          new->status = 1;
          new->cur_time = time(NULL);
          memcpy(new->iface_name, ifinfo->name, strlen(ifinfo->name));
          ovs_dropped_laststatus_cache_add(new);
      }
      else{
        ovs_drop_cache_lock();
        node->status = 1;
        node->cur_time = time(NULL);
        ovs_drop_cache_unlock();

        //ovs_dropped_laststatus_cache_timeout_free(ifinfo);

        DEBUG(OVS_EVENTS_PLUGIN "1 cache status:%d, name:%s\n", node->status, node->iface_name);
      }

      if(ovs_events_ctx.config.config_debug)
        DEBUG(OVS_EVENTS_PLUGIN "ovs interface tables statistics dropped, iface name:%s, dropped counter, rx:%ld, tx:%ld\n", ifinfo->name, rx_dropped_counter, tx_dropped_counter);

      return 0;
  }
  else{
      if(have_dropped_field){
          char *name = ifinfo->name;
          struct ovs_dropped_laststatus_cache * node = ovs_dropped_laststatus_cache_lookup(name);
          if(node){
            //WARNING(OVS_EVENTS_PLUGIN "2 cache status:%d, name:%s\n", node->status, node->iface_name);
            if(node->status == 1){
               ovs_drop_cache_lock();
               node->status = 2; 
               node->cur_time = time(NULL);
               ovs_drop_cache_unlock();

               ifinfo->within_flag = 1;

               if(ovs_events_ctx.config.config_debug)
                    WARNING(OVS_EVENTS_PLUGIN "cache ovs interface tables statistics dropped, iface name:%s, dropped counter, rx:%ld, tx:%ld\n", ifinfo->name, rx_dropped_counter, tx_dropped_counter);

               return 0;
            }
          }

      ovs_dropped_laststatus_cache_timeout_free(ifinfo);
      }


      if(ovs_events_ctx.config.config_debug)
        WARNING(OVS_EVENTS_PLUGIN "ovs interface tables statistics not drop, iface name:%s, dropped counter, rx:%ld, tx:%ld\n", ifinfo->name, rx_dropped_counter, tx_dropped_counter);
      return -1;
  }
  return -1;
}

/* Get OVS DB interface information and stores it into
 * ovs_events_iface_info_t structure */
static int ovs_events_get_iface_info(yajl_val jobject_old, yajl_val jobject_new,
                                     ovs_events_iface_info_t *ifinfo) {
  yajl_val jexternal_ids = NULL;
  yajl_val jvalue = NULL;
  yajl_val juuid = NULL;

  /* check YAJL type */
  if ((!YAJL_IS_OBJECT(jobject_old)) && (!YAJL_IS_OBJECT(jobject_new)))
    return -1;

  /* zero the interface info structure */
  memset(ifinfo, 0, sizeof(*ifinfo));

  /* try to find external_ids, name and link_state fields */
  jexternal_ids = ovs_utils_get_value_by_key(jobject_new, "external_ids");
  if (jexternal_ids == NULL || ifinfo == NULL)
    return -1;

  /* get iface-id from external_ids field */
  jvalue = ovs_utils_get_map_value(jexternal_ids, "iface-id");
  if (jvalue != NULL && YAJL_IS_STRING(jvalue))
    sstrncpy(ifinfo->ext_iface_id, YAJL_GET_STRING(jvalue),
             sizeof(ifinfo->ext_iface_id));

  /* get vm-uuid from external_ids field */
  jvalue = ovs_utils_get_map_value(jexternal_ids, "vm-uuid");
  if (jvalue != NULL && YAJL_IS_STRING(jvalue))
    sstrncpy(ifinfo->ext_vm_uuid, YAJL_GET_STRING(jvalue),
             sizeof(ifinfo->ext_vm_uuid));

  /* get interface uuid */
  jvalue = ovs_utils_get_value_by_key(jobject_new, "_uuid");
  if (jvalue == NULL || !YAJL_IS_ARRAY(jvalue) ||
      YAJL_GET_ARRAY(jvalue)->len != 2)
    return -1;
  juuid = YAJL_GET_ARRAY(jvalue)->values[1];
  if (juuid == NULL || !YAJL_IS_STRING(juuid))
    return -1;
  sstrncpy(ifinfo->uuid, YAJL_GET_STRING(juuid), sizeof(ifinfo->uuid));

  /* get interface name */
  jvalue = ovs_utils_get_value_by_key(jobject_new, "name");
  if (jvalue == NULL || !YAJL_IS_STRING(jvalue))
    return -1;
  sstrncpy(ifinfo->name, YAJL_GET_STRING(jvalue), sizeof(ifinfo->name));

  //WARNING(OVS_EVENTS_PLUGIN ": 111rxtx_dropped:%s\n",ifinfo->name); 
  return ovs_dropped_get_statistics_info(jobject_old, jobject_new, ifinfo);

}

/* Process OVS DB update table event. It handles link status update event(s)
 * and dispatches the value(s) to collectd if interface name matches one of
 * interfaces specified in configuration file.
 */
static void ovs_events_table_update_cb(yajl_val jupdates) {
  yajl_val jold_val = NULL;
  yajl_val jnew_val = NULL;
  yajl_val jupdate = NULL;
  yajl_val jrow_update = NULL;
  ovs_events_iface_info_t ifinfo;

  /* JSON "Interface" table update example:
   * ---------------------------------
   * {"Interface":
   *  {
   *   "9adf1db2-29ca-4140-ab22-ae347a4484de":
   *    {
   *     "new":
   *      {
   *       "name":"br0",
   *       "link_state":"up"
   *      },
   *     "old":
   *      {
   *       "link_state":"down"
   *      }
   *    }
   *  }
   * }
   */
  if (!YAJL_IS_OBJECT(jupdates) || !(YAJL_GET_OBJECT(jupdates)->len > 0)) {
    ERROR(OVS_EVENTS_PLUGIN ": unexpected OVS DB update event received");
    return;
  }
  /* verify if this is a table event */
  jupdate = YAJL_GET_OBJECT(jupdates)->values[0];
  if (!YAJL_IS_OBJECT(jupdate)) {
    ERROR(OVS_EVENTS_PLUGIN ": unexpected table update event received");
    return;
  }
  /* go through all row updates  */
  for (size_t row_index = 0; row_index < YAJL_GET_OBJECT(jupdate)->len;
       ++row_index) {
    jrow_update = YAJL_GET_OBJECT(jupdate)->values[row_index];

    /* check row update */
    jold_val = ovs_utils_get_value_by_key(jrow_update, "old");
    if (jold_val == NULL) {
      ERROR(OVS_EVENTS_PLUGIN ": unexpected row update received");
      return;
    }

    jnew_val = ovs_utils_get_value_by_key(jrow_update, "new");
    if (jnew_val == NULL) {
      ERROR(OVS_EVENTS_PLUGIN ": unexpected row update received");
      return;
    }


    /* get OVS DB interface information */
    if (ovs_events_get_iface_info(jold_val, jnew_val, &ifinfo) < 0) {
      DEBUG(OVS_EVENTS_PLUGIN
            " :unexpected interface information data received");
    }
    else{
        if (!(strstr(ifinfo.name, "br-"))) {
		if (ovs_events_config_iface_exists(ifinfo.name) != 0) {
		    DEBUG("name=%s, uuid=%s, ext_iface_id=%s, ext_vm_uuid=%s", ifinfo.name,
			ifinfo.uuid, ifinfo.ext_iface_id, ifinfo.ext_vm_uuid);
		    /* dispatch notification */
		    ovs_events_dispatch_notification(&ifinfo);
		}
        }
    }
    
  }
}


/* Setup OVS DB table callback. It subscribes to OVS DB 'Interface' table
 * to receive link status event(s).
 */
static void ovs_events_conn_initialize(ovs_db_t *pdb) {
  const char tb_name[] = "Interface";
  const char *columns[] = {"_uuid", "external_ids", "name",
                           "statistics", NULL};

  /* register update link status event if needed */
  if (ovs_events_ctx.config.send_notification) {
    if (!ovs_event_notifier_register_once) {
      if (ovs_events_ctx.config.event_type & LINK_DROP) {
        ovs_event_notifier_register(&rxtx_drop_nb);
      }

      ovs_event_notifier_register_once = 1;
    }
    if (ovs_events_ctx.config.event_type & (LINK_DROP)) {
      int ret = ovs_db_table_cb_register(pdb, tb_name, columns,
                                       ovs_events_table_update_cb, NULL,
                                       OVS_DB_TABLE_CB_FLAG_MODIFY);
      if (ret < 0) {
        ERROR(OVS_EVENTS_PLUGIN ": register OVS DB update callback failed");
        return;
      }
    }
  }
  OVS_EVENTS_CTX_LOCK { ovs_events_ctx.is_db_available = 1; }
  DEBUG(OVS_EVENTS_PLUGIN ": OVS DB connection has been initialized");
}

/* OVS DB terminate connection notification callback */
static void ovs_events_conn_terminate() {
  const char msg[] = "OVS DB connection has been lost";
  if (ovs_events_ctx.config.send_notification)
    ovs_events_dispatch_terminate_notification(msg);
  WARNING(OVS_EVENTS_PLUGIN ": %s", msg);
  OVS_EVENTS_CTX_LOCK { ovs_events_ctx.is_db_available = 0; }
}


/* Initialize OVS plugin */
static int ovs_events_plugin_init(void) {
  OVS_DROP_INIT_LIST_HEAD(&drop_head);

  ovs_db_t *ovs_db = NULL;
  ovs_db_callback_t cb = {.post_conn_init = ovs_events_conn_initialize,
                          .post_conn_terminate = ovs_events_conn_terminate};

  DEBUG(OVS_EVENTS_PLUGIN ": OVS DB address=%s, service=%s, unix=%s",
        ovs_events_ctx.config.ovs_db_node, ovs_events_ctx.config.ovs_db_serv,
        ovs_events_ctx.config.ovs_db_unix);

  /* generate OVS DB select condition based on list on configured interfaces */
  ovs_events_ctx.ovs_db_select_params = ovs_events_get_select_params();
  if (ovs_events_ctx.ovs_db_select_params == NULL) {
    ERROR(OVS_EVENTS_PLUGIN ": fail to get OVS DB select condition");
    goto ovs_events_failure;
  }

  /* initialize OVS DB */
  ovs_db = ovs_db_init(ovs_events_ctx.config.ovs_db_node,
                       ovs_events_ctx.config.ovs_db_serv,
                       ovs_events_ctx.config.ovs_db_unix, &cb);
  if (ovs_db == NULL) {
    ERROR(OVS_EVENTS_PLUGIN ": fail to connect to OVS DB server");
    goto ovs_events_failure;
  }

  /* store OVS DB handler */
  OVS_EVENTS_CTX_LOCK { ovs_events_ctx.ovs_db = ovs_db; }

  DEBUG(OVS_EVENTS_PLUGIN ": plugin has been initialized");
  return 0;

ovs_events_failure:
  ERROR(OVS_EVENTS_PLUGIN ": plugin initialize failed");
  /* release allocated memory */
  ovs_events_config_free();
  return -1;
}

/* Shutdown OVS plugin */
static int ovs_events_plugin_shutdown(void) {
  /* destroy OVS DB */
  if (ovs_db_destroy(ovs_events_ctx.ovs_db))
    ERROR(OVS_EVENTS_PLUGIN ": OVSDB object destroy failed");

  /* release memory allocated for config */
  ovs_events_config_free();

  /* free the dropped cache  */
  ovs_dropped_laststatus_cache_free();

  /* reset the OVS event notify chain.*/
  OVS_EVENT_NOTIFIER_INIT(ovs_event_chain);

  DEBUG(OVS_EVENTS_PLUGIN ": plugin has been destroyed");
  return 0;
}

/* Register OVS plugin callbacks */
void module_register(void) {
  plugin_register_complex_config(OVS_EVENTS_PLUGIN, ovs_events_plugin_config);
  plugin_register_init(OVS_EVENTS_PLUGIN, ovs_events_plugin_init);
  plugin_register_shutdown(OVS_EVENTS_PLUGIN, ovs_events_plugin_shutdown);
}
