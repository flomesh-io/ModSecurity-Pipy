#include "pipy/nmi.h"
#include <ctype.h>
#include <search.h>
#include <stdlib.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rules_set.h>

#ifdef __GNUC__
#define AUTO(x) char *x __attribute__((cleanup(free_char)))
#else
#define AUTO(x) char *x
#endif

#define log(msg_, ...) fprintf(msc->file, (msg_), ##__VA_ARGS__);

#define HASH_COUNT 1024

static void free_char(char **pvariable) { free(*pvariable); }

enum {
  id_var_inbound,
  id_var_native,
  id_var_intervene,
  id_var_msc_logs,
  id_var_rules_file,
  id_var_rules_remote,
  id_var_rules,
  id_var_msc_tx_id,
};

typedef struct MSC {
  ModSecurity *modsec;
  FILE *file;
} MSC;

static unsigned long crcTable[256];

static MSC *msc = NULL;

typedef int (*fn_add_header)(Transaction *transaction, const unsigned char *key,
                             size_t len_key, const unsigned char *value,
                             size_t len_value);

typedef struct _pipeline_state {
  RulesSet *rules;
  Transaction *transaction;
  pjs_value start;
  pjs_value body;
  fn_add_header add_header;
  int disruptive;
  pipy_pipeline ppl;
} pipeline_state;

typedef struct Intervention {
  int status;
  char *url;
  char *log;
  int disruptive;
} Intervention;

typedef struct RemoteRule {
  char *key;
  char *url;
} RemoteRule;

static void setup_mcs();
static void pipeline_init(pipy_pipeline ppl, void **user_ptr);
static void pipeline_free(pipy_pipeline ppl, void *user_ptr);
static void pipeline_process(pipy_pipeline ppl, void *user_ptr, pjs_value evt);

static void pipeline_resp_init(pipy_pipeline ppl, void **user_ptr);
static void pipeline_resp_free(pipy_pipeline ppl, void *user_ptr);
static void pipeline_resp_process(pipy_pipeline ppl, void *user_ptr,
                                  pjs_value evt);
void crcgen();
char *get_crc(char *str);

void pipy_module_init() {
  crcgen();
  setup_mcs();
  hcreate(HASH_COUNT);

  pipy_define_variable(id_var_inbound, "__msc_inbound", "mod-sec",
                       pjs_undefined());
  pipy_define_variable(id_var_native, "__msc_tx", "mod-sec", pjs_undefined());
  pipy_define_variable(id_var_intervene, "__msc_intervention", "mod-sec",
                       pjs_undefined());
  pipy_define_variable(id_var_msc_logs, "__msc_warnings", "mod-sec",
                       pjs_undefined());
  pipy_define_variable(id_var_msc_tx_id, "__msc_transaction_id", "mod-sec",
                       pjs_undefined());

  pipy_define_variable(id_var_rules_file, "__msc_rules_file", "mod-sec",
                       pjs_undefined());
  pipy_define_variable(id_var_rules_remote, "__msc_rules_remote", "mod-sec",
                       pjs_undefined());
  pipy_define_variable(id_var_rules, "__msc_rules", "mod-sec", pjs_undefined());

  pipy_define_pipeline("request", pipeline_init, pipeline_free,
                       pipeline_process);

  pipy_define_pipeline("response", pipeline_resp_init, pipeline_resp_free,
                       pipeline_resp_process);
}

void pipy_module_free() {
  msc_cleanup(msc->modsec);
  fclose(msc->file);
}

/*
    Helpers
*/
static void free_tx(void *data);

static Intervention *process_intervention(Transaction *transaction);
static char *get_prop(pjs_value head, char *prop);
static int get_int_prop(pjs_value head, char *prop);
static int check(Intervention *iv, pipy_pipeline ppl);
static void free_iv(Intervention *iv);
static int hdrCb(pjs_value k, pjs_value v, void *user_ptr);
static void add_warning(void *data, char *str);
static void update_intervene(pipy_pipeline ppl, char *field, pjs_value value);
static char *to_string(pjs_value v);
static int rules_loaded(pipeline_state *state, char *file, RemoteRule *remote,
                        char *rules);
static char *check_rules_var(pipy_pipeline ppl, int var);
static RemoteRule *get_remote_rule(pipy_pipeline ppl);
/*
    Request Pipeline
*/

static void pipeline_init(pipy_pipeline ppl, void **user_ptr) {
  pipeline_state *state = calloc(1, sizeof(pipeline_state));
  state->ppl = ppl;
  state->add_header = msc_add_n_request_header;

  // state->rules = msc_create_rules_set();

  AUTO(rules_file) = check_rules_var(ppl, id_var_rules_file);
  AUTO(rules) = check_rules_var(ppl, id_var_rules);
  RemoteRule *remote = get_remote_rule(ppl);

  const char *error = NULL;
  int ret;
  if (!rules_loaded(state, rules_file, remote, rules)) {
    if (rules_file) {
      log("Loading rule file %s\n", rules_file);
      ret = msc_rules_add_file(state->rules, rules_file, &error);
      if (ret < 0) {
        log("Problems loading the file rules --\n");
        log("%s\n", error);
        exit(1);
      }
    }

    if (remote) {
      log("Loading remote rule file %s\n", remote->url);
      int ret =
          msc_rules_add_remote(state->rules, remote->key, remote->url, &error);
      free(remote);

      if (ret < 0) {
        log("Problems loading the remote file rules --\n");
        log("%s\n", error);
        exit(1);
      }
    }

    if (rules) {
      log("Loading plain rules\n%s\n", rules);
      ret = msc_rules_add(state->rules, rules, &error);
      if (ret < 0) {
        log("Problems loading the plain rules. --\n");
        log("%s\n", error);
        exit(1);
      }
    }

    if (!rules_file && !remote && !rules) {
      log("No Rules provided. You need to provide rules, for rules from file use variable __msc_rules_file,\
for remote rules use __msc_rules_remote or for direct inclusion of rules set variable __msc_rules\n");
      exit(1);
    }
  }

  pjs_value tx_id = pjs_undefined();
  pipy_get_variable(ppl, id_var_msc_tx_id, tx_id);

  if (pjs_is_undefined(tx_id) || (pjs_type_of(tx_id) != PJS_TYPE_STRING) ||
      pjs_is_empty_string(tx_id))
    state->transaction =
        msc_new_transaction(msc->modsec, state->rules, (void *)state);
  else
    state->transaction = msc_new_transaction_with_id(
        msc->modsec, state->rules, to_string(tx_id), (void *)state);

  free_iv(process_intervention(state->transaction));

  pjs_value tx = pjs_native((void *)state, free_tx);
  pipy_set_variable(ppl, id_var_native, tx);

  update_intervene(ppl, "disruptive", pjs_boolean(0));
  update_intervene(ppl, "status", pjs_undefined());
  update_intervene(ppl, "url", pjs_undefined());
  update_intervene(ppl, "log", pjs_undefined());

  *user_ptr = (void *)state;
}

static void pipeline_free(pipy_pipeline ppl, void *user_ptr) {
  pipeline_state *state = (pipeline_state *)user_ptr;
  pjs_free(state->start);
  pjs_free(state->body);

  fflush(msc->file);
}

static void pipeline_process(pipy_pipeline ppl, void *user_ptr, pjs_value evt) {
  pipeline_state *state = (pipeline_state *)user_ptr;
  if (pipy_is_MessageStart(evt)) {
    if (!state->start) {

      pjs_value inbound = pjs_undefined();
      pipy_get_variable(ppl, id_var_inbound, inbound);

      if (pjs_is_undefined(inbound) ||
          pjs_type_of(inbound) != PJS_TYPE_OBJECT) {
        log("__msc_inbound variable is not set or is not an object containing "
            "PJS __inbound object properties.\n");
        log("Module is not able to work, and all ModSecurity checks will be "
            "turned off.\n");
        log("For this module to work, __msc_inbound need to contain properties "
            "from PJS __inbound object.\n");
        update_intervene(ppl, "status", pjs_number((double)200));
        pipy_output_event(ppl, evt);
        return;
      }

      state->start = pjs_hold(evt);
      state->body = pjs_hold(pipy_Data_new(0, 0));

      AUTO(server) = get_prop(inbound, "localAddress");
      int sport = get_int_prop(inbound, "localPort");

      AUTO(client) = get_prop(inbound, "remoteAddress");
      int cport = get_int_prop(inbound, "remotePort");

      pjs_value head = pipy_MessageStart_get_head(evt);
      pjs_value pjs_header = pjs_undefined();
      pjs_value v_headers = pjs_string("headers", -1);
      pjs_object_get_property(head, v_headers, pjs_header);

      AUTO(host) = get_prop(pjs_header, "host");
      AUTO(path) = get_prop(head, "path");
      AUTO(pscheme) = get_prop(head, "scheme");
      char scheme[8] = "http://";

      if (pscheme != NULL && strlen(pscheme) > 0)
        strncpy(scheme, pscheme, sizeof(scheme));

      AUTO(tmpprotocol) = get_prop(head, "protocol");
      AUTO(method) = get_prop(head, "method");

      int uri_size = 8 + strlen(host) + strlen(path);
      AUTO(uri) = (char *)malloc(uri_size);
      snprintf(uri, uri_size, "%s%s%s", scheme, host, path);

      strtok(tmpprotocol, "/");
      char *protocol = strtok(NULL, "/");

      msc_process_connection(state->transaction, (const char *)client, cport,
                             (const char *)server, sport);
      state->disruptive = check(process_intervention(state->transaction), ppl);

      if (!state->disruptive) {
        msc_process_uri(state->transaction, uri, method, protocol);
        state->disruptive =
            check(process_intervention(state->transaction), ppl);
        if (!state->disruptive) {
          pjs_object_iterate(pjs_header, hdrCb, user_ptr);
          msc_process_request_headers(state->transaction);
          state->disruptive =
              check(process_intervention(state->transaction), ppl);
        }
      }
    }
  } else if (pipy_is_Data(evt)) {
    if (state->start && !state->disruptive) {
      pipy_Data_push(state->body, evt);
    }
  } else if (pipy_is_MessageEnd(evt)) {
    if (state->start && !state->disruptive) {
      int size = pipy_Data_get_size(state->body) + 1;
      char buf[size];
      pipy_Data_get_data(state->body, buf, size);

      msc_append_request_body(state->transaction, (const unsigned char *)buf,
                              size);
      msc_process_request_body(state->transaction);
      state->disruptive = check(process_intervention(state->transaction), ppl);

      if (!state->disruptive)
        update_intervene(ppl, "status", pjs_number((double)200));

      pjs_free(state->start);
      pjs_free(state->body);
    }
  }
  pipy_output_event(ppl, evt);
}

/*
    Response Pipeline
*/

static void pipeline_resp_init(pipy_pipeline ppl, void **user_ptr) {
  pipeline_state *state = calloc(1, sizeof(pipeline_state));
  state->ppl = ppl;
  state->add_header = msc_add_n_response_header;
  pjs_value tx = pjs_undefined();
  pipy_get_variable(ppl, id_var_native, tx);
  if (pjs_is_native(tx) && !pjs_is_null(tx)) {
    pipeline_state *req = (pipeline_state *)pjs_native_ptr(tx);
    if (!req) {
      log("variable __msc_tx is not a native var or it points to a NULL "
          "pointer.\n");
      state->transaction = NULL;
    } else
      state->transaction = req->transaction;
  } else {
    log("variable __msc_tx is not a native var. Response scanning will be "
        "disabled\n");
    state->transaction = NULL;
  }
  *user_ptr = (void *)state;
}

static void pipeline_resp_free(pipy_pipeline ppl, void *user_ptr) {
  pipeline_state *state = (pipeline_state *)user_ptr;

  pjs_free(state->start);
  pjs_free(state->body);
  fflush(msc->file);
  free(state);
}

static void pipeline_resp_process(pipy_pipeline ppl, void *user_ptr,
                                  pjs_value evt) {
  pipeline_state *state = (pipeline_state *)user_ptr;

  if (!state->transaction) {
    log("Skipping Response scanning due to missing transaction object\n");
    update_intervene(ppl, "status", pjs_number((double)200));
    pipy_output_event(ppl, evt);
    return;
  }

  if (pipy_is_MessageStart(evt)) {
    if (!state->start) {
      state->start = pjs_hold(evt);
      state->body = pjs_hold(pipy_Data_new(0, 0));

      pjs_value head = pipy_MessageStart_get_head(evt);
      pjs_value pjs_header = pjs_undefined();
      pjs_value v_headers = pjs_string("headers", -1);
      pjs_object_get_property(head, v_headers, pjs_header);

      AUTO(protocol) = get_prop(head, "protocol");
      int status = get_int_prop(head, "status");

      pjs_object_iterate(pjs_header, hdrCb, user_ptr);
      msc_process_response_headers(state->transaction, status,
                                   (const char *)protocol);
      state->disruptive = check(process_intervention(state->transaction), ppl);

      if (!state->disruptive)
        update_intervene(ppl, "status", pjs_number((double)200));
    }
  } else if (pipy_is_Data(evt)) {
    if (state->start && !state->disruptive) {
      pipy_Data_push(state->body, evt);
    }
  } else if (pipy_is_MessageEnd(evt)) {
    if (state->start && !state->disruptive) {
      int size = pipy_Data_get_size(state->body) + 1;
      char buf[size];
      pipy_Data_get_data(state->body, buf, size);

      msc_append_response_body(state->transaction, (const unsigned char *)buf,
                               size);
      msc_process_response_body(state->transaction);
      state->disruptive = check(process_intervention(state->transaction), ppl);

      if (!state->disruptive)
        update_intervene(ppl, "status", pjs_number((double)200));

      pjs_free(state->start);
      pjs_free(state->body);
    }
  }
  pipy_output_event(ppl, evt);
}

/*
    ModSecurity Interface
*/
static void logCb(void *data, const void *ruleMessagev);

static void setup_mcs() {
  msc = (MSC *)calloc(1, sizeof(MSC));
  msc->file = fopen("log.txt", "w+");
  if (msc->file == NULL) {
    printf("Error opening log file");
    exit(1);
  }
  msc->modsec = msc_init();
  msc_set_connector_info(
      msc->modsec,
      "ModSecurity Pipy Connector v0.0.1-alpha (Pipy NMI + ModeSecurity API)");

  msc_set_log_cb(msc->modsec, logCb);
  log("%s\n", msc_who_am_i(msc->modsec));
}

static Intervention *process_intervention(Transaction *transaction) {
  ModSecurityIntervention it;
  it.status = 200;
  it.url = NULL;
  it.log = NULL;
  it.disruptive = 0;

  if (msc_intervention(transaction, &it) == 0) {
    return NULL;
  }

  Intervention *ret = (Intervention *)calloc(1, sizeof(Intervention));
  ret->disruptive = it.disruptive;
  ret->status = it.status;
  ret->log = NULL;
  ret->url = NULL;

  if (it.log == NULL) {
    it.log = strdup("(no log message was specified)");
  }

  log("Log: %s\n", it.log);
  ret->log = strdup(it.log);
  free(it.log);
  it.log = NULL;

  if (it.url != NULL) {
    log("intervention, redirect to: %s", it.url);
    log(" with status code: %d\n", it.status);
    ret->url = strdup(it.url);
    ret->status = it.status;
    free(it.url);
    it.url = NULL;
  }

  if (it.status != 200) {
    log("intervention, returning code: %d\n", it.status);
    ret->status = it.status;
  }

  return ret;
}

static void logCb(void *data, const void *ruleMessagev) {
  if (ruleMessagev == NULL) {
    log("I've got a call but the message was null :(\n");
    return;
  }
  log("%s\n", (char *)ruleMessagev);
  add_warning(data, (char *)ruleMessagev);
}

/*
    Helpers
*/

static void free_tx(void *data) {
  pipeline_state *state = (pipeline_state *)data;

  msc_process_logging(state->transaction);
  msc_transaction_cleanup(state->transaction);
  // msc_rules_cleanup(state->rules);
  free(state);
  fflush(msc->file);
}

static void iv_to_pjs(pipy_pipeline ppl, Intervention *iv) {
  if (iv == NULL)
    return;

  update_intervene(ppl, "disruptive", pjs_boolean(iv->disruptive));
  update_intervene(ppl, "status", pjs_number((double)iv->status));

  pjs_value url = pjs_undefined();
  if (iv->url != NULL)
    url = pjs_string(iv->url, strlen(iv->url));

  update_intervene(ppl, "url", url);

  pjs_value log = pjs_undefined();
  if (iv->log != NULL)
    log = pjs_string(iv->log, strlen(iv->log));

  update_intervene(ppl, "log", log);
}

static char *to_string(pjs_value v) {
  int size = pjs_string_get_utf8_size(v);
  char *ret = (char *)malloc(size + 1);
  pjs_string_get_utf8_data(v, ret, size);
  ret[size] = '\0';
  return ret;
}

static int hdrCb(pjs_value k, pjs_value v, void *user_ptr) {
  pipeline_state *state = (pipeline_state *)user_ptr;

  AUTO(key) = to_string(k);
  AUTO(value) = to_string(v);
  state->add_header(state->transaction, (const unsigned char *)key, strlen(key),
                    (const unsigned char *)value, strlen(value));
  return 1;
}

static int get_int_prop(pjs_value head, char *prop) {
  pjs_value pjs_prop = pjs_undefined();
  pjs_value v_prop = pjs_string(prop, -1);
  pjs_object_get_property(head, v_prop, pjs_prop);
  return (int)pjs_to_number(pjs_prop);
}

static char *get_prop(pjs_value head, char *prop) {
  pjs_value pjs_prop = pjs_undefined();
  pjs_value v_prop = pjs_string(prop, -1);
  pjs_object_get_property(head, v_prop, pjs_prop);
  return to_string(pjs_prop);
}

static int check(Intervention *iv, pipy_pipeline ppl) {
  if (iv == NULL)
    return 0;

  iv_to_pjs(ppl, iv);
  free_iv(iv);
  return 1;
}

static void add_warning(void *data, char *str) {
  pipeline_state *state = (pipeline_state *)data;
  pjs_value arr = pjs_undefined();

  pipy_get_variable(state->ppl, id_var_msc_logs, arr);
  if (pjs_is_undefined(arr) || pjs_type_of(arr) != PJS_TYPE_OBJECT) {
    arr = pjs_object();
    pipy_set_variable(state->ppl, id_var_msc_logs, arr);
  }

  pjs_array_push(arr, pjs_string(str, strlen(str)));
}

static void update_intervene(pipy_pipeline ppl, char *field, pjs_value value) {
  pjs_value obj = pjs_undefined();
  pipy_get_variable(ppl, id_var_intervene, obj);
  if (pjs_is_undefined(obj) || pjs_type_of(obj) != PJS_TYPE_OBJECT) {
    obj = pjs_object();
    pipy_set_variable(ppl, id_var_intervene, obj);
  }

  pjs_object_set_property(obj, pjs_string(field, strlen(field)), value);
}

static void free_iv(Intervention *iv) {
  if (iv == NULL)
    return;
  if (iv->url)
    free(iv->url);
  if (iv->log)
    free(iv->log);
  free(iv);
  iv = NULL;
}

void crcgen() {
  unsigned long crc, poly;
  int i, j;

  poly = 0xEDB88320L;
  for (i = 0; i < 256; i++) {
    crc = i;
    for (j = 8; j > 0; j--) {
      if (crc & 1)
        crc = (crc >> 1) ^ poly;
      else
        crc >>= 1;
    }
    crcTable[i] = crc;
  }
}

char *get_crc(char *str) {
  register unsigned long crc;
  char *t;

  crc = 0xFFFFFFFF;
  for (t = str; *t != '\0'; t++) {
    crc = ((crc >> 8) & 0x00FFFFFF) ^ crcTable[(crc ^ *t) & 0xFF];
  }

  crc = crc ^ 0xFFFFFFFF;

  const int n = snprintf(NULL, 0, "%lu", crc);
  char *buf = malloc(n + 1);
  snprintf(buf, n + 1, "%lu", crc);
  return buf;
}

static char *make_key(char *file, RemoteRule *remote, char *rules) {
  size_t len = 0;
  if (file)
    len = len + strlen(file);
  if (remote)
    len = len + strlen(remote->key) + strlen(remote->url);
  if (rules)
    len = len + strlen(rules);

  char *buf = (char *)malloc(len);
  if (file)
    strlcat(buf, file, len);
  if (remote) {
    strlcat(buf, remote->key, len);
    strlcat(buf, remote->url, len);
  }
  if (rules)
    strlcat(buf, rules, len);

  return buf;
}

static int rules_loaded(pipeline_state *state, char *file, RemoteRule *remote,
                        char *rules) {
  ENTRY e, *ep;
  AUTO(key) = make_key(file, remote, rules);
  e.key = get_crc(key);
  ;
  ep = hsearch(e, FIND);
  if (ep != NULL) {
    state->rules = (RulesSet *)ep->data;
    return 1;
  }
  state->rules = msc_create_rules_set();
  e.data = (void *)state->rules;
  ep = hsearch(e, ENTER);
  if (ep == NULL) {
    log("Warning: Unable to add entry into hash table due to size limit "
        "reached. Going further rules will be loaded on each pipeline init \n");
  }
  return 0;
}

static char *check_rules_var(pipy_pipeline ppl, int var) {
  pjs_value rule = pjs_undefined();
  pipy_get_variable(ppl, var, rule);
  if (pjs_is_undefined(rule) || (pjs_type_of(rule) != PJS_TYPE_STRING) ||
      pjs_is_empty_string(rule))
    return NULL;

  return to_string(rule);
}

static RemoteRule *get_remote_rule(pipy_pipeline ppl) {
  pjs_value rule = pjs_undefined();
  pipy_get_variable(ppl, id_var_rules_remote, rule);
  if (pjs_is_undefined(rule) || (pjs_type_of(rule) != PJS_TYPE_OBJECT))
    return NULL;

  RemoteRule *remote = (RemoteRule *)calloc(1, sizeof(RemoteRule));

  const char *error = NULL;

  remote->key = get_prop(rule, "key");
  remote->url = get_prop(rule, "url");

  if (!remote->key)
    remote->key = strdup("modsec-pipy");

  if (!remote->url) {
    log("No Remote URL provided for rules file\n");
    exit(1);
  }

  return remote;
}