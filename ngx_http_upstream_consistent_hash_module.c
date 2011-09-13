

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


#define CONSISTENT_DEBUG 0

#define MMC_CONSISTENT_BUCKETS 65536


typedef struct {
    ngx_array_t                 *values;
    ngx_array_t                 *lengths;
    void                        *data; /* store the hash buckets*/
} ngx_http_upstream_consistent_hash_srv_conf_t;

typedef struct {
    uint32_t                     point;
    ngx_http_upstream_rr_peer_t *rr_peer;
} ngx_http_upstream_consistent_hash_node;

typedef struct {
    ngx_uint_t                                    nnodes;
    ngx_http_upstream_consistent_hash_node       *nodes;
} ngx_http_upstream_consistent_hash_continuum;

typedef struct {
    ngx_http_upstream_consistent_hash_node       *bucket[MMC_CONSISTENT_BUCKETS];
    ngx_http_upstream_consistent_hash_continuum  *continuum;
} ngx_http_upstream_consistent_hash_buckets;

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t              rrp;
    ngx_http_upstream_consistent_hash_buckets    *buckets;
    uint32_t                                      point;
    u_char                                        tries;
    ngx_event_get_peer_pt                         get_rr_peer;
} ngx_http_upstream_consistent_hash_peer_data_t;

static ngx_int_t ngx_http_upstream_init_consistent_hash(ngx_conf_t *, 
        ngx_http_upstream_srv_conf_t*);
static ngx_int_t ngx_http_upstream_init_consistent_hash_peer(
        ngx_http_request_t*, ngx_http_upstream_srv_conf_t*);
static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_consistent_hash_find_rr_peer(
        ngx_http_upstream_rr_peers_t *peers, struct sockaddr  *addr);
static int32_t ngx_http_upstream_consistent_hash_node_point(u_char *str, 
        size_t len);
static int ngx_http_upstream_consistent_hash_compare_continuum_nodes (
        const ngx_http_upstream_consistent_hash_node*, 
        const ngx_http_upstream_consistent_hash_node*);
static ngx_http_upstream_consistent_hash_node* 
ngx_http_upstream_consistent_hash_find(
        ngx_http_upstream_consistent_hash_continuum*, uint32_t);
#if (CONSISTENT_DEBUG)
static void ngx_http_upstream_consistent_hash_print_continuum (ngx_conf_t*, 
        ngx_http_upstream_consistent_hash_continuum*);
static void ngx_http_upstream_consistent_hash_print_buckets (ngx_conf_t *cf, 
        ngx_http_upstream_consistent_hash_buckets*);
#endif
static ngx_int_t ngx_http_upstream_get_consistent_hash_peer(
        ngx_peer_connection_t*, void*);
static char * ngx_http_upstream_consistent_hash(ngx_conf_t*,
        ngx_command_t*, void*);
static void * ngx_http_upstream_consistent_hash_create_srv_conf(ngx_conf_t *cf);


static ngx_command_t  ngx_http_upstream_consistent_hash_commands[] = { 

    {   ngx_string("consistent_hash"),
        NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
        ngx_http_upstream_consistent_hash,
        0,
        0,
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_consistent_hash_module_ctx = { 
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_consistent_hash_create_srv_conf, /* create server configuration */
    NULL,                                              /* merge server configuration */ 

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_consistent_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_consistent_hash_module_ctx, /* module context */
    ngx_http_upstream_consistent_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_upstream_init_consistent_hash(ngx_conf_t *cf, 
        ngx_http_upstream_srv_conf_t *us)
{
    /* ip max 15, :port max 6, maxweight is highest number of uchar */
    u_char                                       *last, hash_data[28];
    uint32_t                                      step;
    ngx_uint_t                                    i, j, k, n;
    ngx_uint_t                                    real_nodes, points_per_node;
    ngx_http_upstream_server_t                   *server;
    ngx_http_upstream_rr_peer_t                  *rr_peer;
    ngx_http_upstream_rr_peers_t                 *prr_peers;
    ngx_http_upstream_consistent_hash_buckets    *buckets;
    ngx_http_upstream_consistent_hash_continuum       *continuum;
    ngx_http_upstream_consistent_hash_srv_conf_t      *uchscf;


    uchscf = ngx_http_conf_upstream_srv_conf(us,
            ngx_http_upstream_consistent_hash_module);
    if (uchscf == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    prr_peers = us->peer.data;
    us->peer.init = ngx_http_upstream_init_consistent_hash_peer;

    buckets = ngx_pcalloc(cf->pool, 
            sizeof(ngx_http_upstream_consistent_hash_buckets));

    if (!us->servers) {
        return NGX_ERROR;
    }

    server = us->servers->elts;

    n = real_nodes = 0;
    for (i = 0; i < us->servers->nelts; i++) {
        n += server[i].naddrs;
        real_nodes += server[i].weight * server[i].naddrs;
    }
    
    /*
     * The optimal points number is Q/S
     * See the section 6.2 from the paper 'Dynamo: Amazon's Highly Available
     * Key-value Store'
     */
    points_per_node = (ngx_uint_t) MMC_CONSISTENT_BUCKETS / real_nodes;
    if (points_per_node == 0) {
        points_per_node = 1;
    }

    continuum = ngx_pcalloc(cf->pool, 
            sizeof(ngx_http_upstream_consistent_hash_continuum));
    continuum->nodes = ngx_palloc(cf->pool, 
            sizeof(ngx_http_upstream_consistent_hash_node) * MMC_CONSISTENT_BUCKETS);

    for (i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++) {

            rr_peer = ngx_http_upstream_consistent_hash_find_rr_peer(prr_peers,
                    server[i].addrs[j].sockaddr);
            if (rr_peer == NULL) {
                return NGX_ERROR;
            }

            for (k = 0; k < (points_per_node * server[i].weight); k++) {
                last = ngx_snprintf(hash_data, 28, "%V-%ui",
                        &server[i].addrs[j].name, k);

                continuum->nodes[continuum->nnodes].point =
                    ngx_http_upstream_consistent_hash_node_point(hash_data, 
                            (last - hash_data));

                continuum->nodes[continuum->nnodes].rr_peer = rr_peer;
                continuum->nnodes++;
            }
        }
    }

    ngx_qsort(continuum->nodes, continuum->nnodes, 
            sizeof(ngx_http_upstream_consistent_hash_node), 
            (const void*) ngx_http_upstream_consistent_hash_compare_continuum_nodes);

    step = (uint32_t) (0xffffffff / MMC_CONSISTENT_BUCKETS);

    for (i = 0; i < MMC_CONSISTENT_BUCKETS; i++) {
        buckets->bucket[i] = 
            ngx_http_upstream_consistent_hash_find(continuum, step * i);
    }

#if (CONSISTENT_DEBUG)
    ngx_http_upstream_consistent_hash_print_continuum(cf, continuum);
    ngx_http_upstream_consistent_hash_print_buckets(cf, buckets);
#endif

    buckets->continuum = continuum;
    uchscf->data = buckets;

    return NGX_OK;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_consistent_hash_find_rr_peer(
        ngx_http_upstream_rr_peers_t *peers, struct sockaddr  *addr)
{
    ngx_uint_t                   i;

    for (i = 0; i < peers->number; i++) {
        if (peers->peer[i].sockaddr == addr) {
            return &peers->peer[i];
        }
    }

    return NULL;
}


/* The md5 hash vaule has better random value with the input string than crc32.
 * And the virtual node can be dispersed uniformly in the ring.
 * */
static int32_t 
ngx_http_upstream_consistent_hash_node_point(u_char *str, size_t len)
{
    u_char     md5_buf[16];
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, str, len);
    ngx_md5_final(md5_buf, &md5);

    return ngx_crc32_long(md5_buf, 16);
}


static int 
ngx_http_upstream_consistent_hash_compare_continuum_nodes(
        const ngx_http_upstream_consistent_hash_node *node1, 
        const ngx_http_upstream_consistent_hash_node *node2)
{
    if (node1->point < node2->point) {
        return -1;
    }
    else if (node1->point > node2->point) {
        return 1;
    }

    return 0;
}


static ngx_http_upstream_consistent_hash_node*
ngx_http_upstream_consistent_hash_find(
        ngx_http_upstream_consistent_hash_continuum *continuum, 
        uint32_t point)
{
    ngx_uint_t mid = 0, lo = 0, hi = continuum->nnodes - 1;

    while (1)
    {
        if (point <= continuum->nodes[lo].point || 
                point > continuum->nodes[hi].point) {
            return &continuum->nodes[lo];
        }

        /* test middle point */
        mid = lo + (hi - lo) / 2;

        /* perfect match */
        if (point <= continuum->nodes[mid].point && 
                point > (mid ? continuum->nodes[mid-1].point : 0)) {
            return &continuum->nodes[mid];
        }

        /* too low, go up */
        if (continuum->nodes[mid].point < point) {
            lo = mid + 1;
        }
        else {
            hi = mid - 1;
        }
    }
}


static ngx_int_t
ngx_http_upstream_init_consistent_hash_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t                                          evaluated_key_to_hash;
    ngx_http_upstream_consistent_hash_srv_conf_t      *uchscf;
    ngx_http_upstream_consistent_hash_peer_data_t     *uchpd;

    uchscf = ngx_http_conf_upstream_srv_conf(us,
            ngx_http_upstream_consistent_hash_module);
    if (uchscf == NULL) {
        return NGX_ERROR;
    }

    uchpd = ngx_pcalloc(r->pool, 
            sizeof(ngx_http_upstream_consistent_hash_peer_data_t));
    if (uchpd == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &uchpd->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_consistent_hash_peer;

    uchpd->buckets = uchscf->data;
    uchpd->tries = 0;

    if (ngx_http_script_run(r, &evaluated_key_to_hash, 
                uchscf->lengths->elts, 0, uchscf->values->elts) == NULL)
    {
        return NGX_ERROR;
    }

    uchpd->point = 
        ngx_crc32_long(evaluated_key_to_hash.data, evaluated_key_to_hash.len);

    uchpd->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_consistent_hash_peer(ngx_peer_connection_t *pc, 
        void *data)
{
    time_t                                         now;
    uint32_t                                       point;
    uintptr_t                                      m;
    ngx_uint_t                                     n, p;
    ngx_http_upstream_rr_peer_t                   *peer;
    ngx_http_upstream_consistent_hash_peer_data_t *uchpd = data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "consistent hash point: %ui, try: %ui", 
                   uchpd->point, pc->tries);

    if (uchpd->tries > 20 || uchpd->rrp.peers->single) {
        return uchpd->get_rr_peer(pc, &uchpd->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    point = uchpd->point;

    for ( ;; ) {

        /* move to other buckets */
        point += 89 * uchpd->tries; 

        p = point % uchpd->rrp.peers->number;

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (!(uchpd->rrp.tried[n] & m)) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get consistent hash peer, hash: %ui %04XA", p, m);

            peer = uchpd->buckets->bucket[point % MMC_CONSISTENT_BUCKETS]->rr_peer;

            /* ngx_lock_mutex(uchpd->rrp.peers->mutex); */

            if (!peer->down) {

                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    break;
                }

                if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                    break;
                }
            }

            uchpd->rrp.tried[n] |= m;

            /* ngx_unlock_mutex(uchpd->rrp.peers->mutex); */

            pc->tries--;
        }

        if (++uchpd->tries >= 20) {
            return uchpd->get_rr_peer(pc, &uchpd->rrp);
        }
    }

    uchpd->rrp.current = p;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* ngx_unlock_mutex(uchpd->rrp.peers->mutex); */

    uchpd->rrp.tried[n] |= m;
    uchpd->point = point;

    return NGX_OK;
}


static void *
ngx_http_upstream_consistent_hash_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_consistent_hash_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_upstream_consistent_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc(): 
     *
     *     conf->lengths = NULL; 
     *     conf->values  = NULL;
     *     conf->data    = NULL;
    */

    return conf;
}


static char *
ngx_http_upstream_consistent_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                    *value;
    ngx_http_script_compile_t                     sc;
    ngx_http_upstream_srv_conf_t                 *uscf;
    ngx_http_upstream_consistent_hash_srv_conf_t *uchscf;

    value = cf->args->elts;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uchscf = ngx_http_conf_upstream_srv_conf(uscf,
            ngx_http_upstream_consistent_hash_module);

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &uchscf->lengths;
    sc.values = &uchscf->values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_consistent_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}


#if (CONSISTENT_DEBUG)
static void 
ngx_http_upstream_consistent_hash_print_continuum (ngx_conf_t *cf, 
        ngx_http_upstream_consistent_hash_continuum *continuum)
{
    ngx_uint_t i;

    printf("print continuum:\n");

    for (i = 0; i < continuum->nnodes; i++) {
        printf("%i: name %.19s point %u\n", (int)i, 
                (char*)continuum->nodes[i].rr_peer->name.data, 
                (unsigned int)continuum->nodes[i].point);
    }
}


static void 
ngx_http_upstream_consistent_hash_print_buckets (ngx_conf_t *cf, 
        ngx_http_upstream_consistent_hash_buckets *buckets)
{
    ngx_uint_t i;

    printf("print buckets:\n");

    for (i = 0; i < MMC_CONSISTENT_BUCKETS; i++) {
        printf("%i: name %s point %u\n", (int)i,
                (char*)buckets->bucket[i]->rr_peer->name.data, 
                (unsigned int)buckets->bucket[i]->point);
    }
}
#endif
