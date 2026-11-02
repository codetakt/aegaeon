/* Research artifact only. All six target cases share a fixed signal recipe.
 * Sidecar writes are outside the measured loop. The call counter and wrapper
 * are common to zero and signal arms; ordinary artifact equivalence is not
 * claimed. Source and resulting machine code are retained by build.py. */
static const char *signal_names[] = {"zero", "lower_tail", "full", "early_half",
    "late_half", "early_short", "late_short", "history"};
static const char *target_names[] = {"ct_eq_32", "hmac_sha256", "hmac_sha256_key", "ct_eq_64", "ct_eq_128", "sha256"};
static unsigned signal_profile, batches[6], active_batch;
static int active_target = -1;
static uint8_t *signal_base, *signal_labels;
static size_t signal_size, signal_stride;
static size_t target_stride(unsigned t) { return t==4 ? 128 : t==3 ? 64 : 32; }
static uint32_t signal_counts[65536];
static uint64_t callback_counts[6], prepared_counts[6];
static FILE *signal_output;

static int target(dudect_config_t *c) {
    if (current_test == TEST_CT_EQ && c->chunk_size == 32) return 0;
    if (current_test == TEST_CT_EQ && c->chunk_size == 64) return 3;
    if (current_test == TEST_CT_EQ && c->chunk_size == 128) return 4;
    if (current_test == TEST_SHA256) return 5;
    if (current_test == TEST_HMAC_SHA256) return 1;
    if (current_test == TEST_HMAC_SHA256_KEY) return 2;
    return -1;
}
static unsigned enabled(unsigned profile, unsigned batch, size_t i, const uint8_t *labels) {
    if (!batch || !labels[i]) return 0;
    switch (profile) {
    case 2: return 1;
    case 3: return batch <= 8;
    case 4: return batch >= 9;
    case 5: return batch <= 2;
    case 6: return batch >= 15;
    case 7: return i != 0 && labels[i-1];
    default: return 0;
    }
}
__attribute__((noinline)) static uint64_t signal_work(uint32_t count) {
    uint64_t x = 0;
    for (uint32_t i=0; i<count; ++i)
        __asm__ __volatile__("addq $1, %0" : "+r"(x) : : "cc");
    return x;
}
static void save_bytes(const void *p, size_t bytes) {
    dudect_require(signal_output && fwrite(p, 1, bytes, signal_output)==bytes,
                   "signal sidecar write");
}
static void assign(dudect_config_t *c, uint8_t *data, uint8_t *classes, unsigned batch) {
    dudect_require(active_target>=0 && active_target<6 &&
                   c->chunk_size==target_stride((unsigned)active_target) &&
                   c->number_measurements<=65536,
                   "six-case signal shape");
    signal_base=data; signal_labels=classes; signal_size=c->number_measurements;
    active_batch=batch; signal_stride=c->chunk_size;
    for (size_t i=0; i<signal_size; ++i)
        signal_counts[i]=32+16*enabled(signal_profile, batch, i, classes);
}
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    active_target=target(c);
#ifdef SENSITIVITY_FIXTURE
    dudect_require(active_target>=0, "fixture target");
    unsigned batch=batches[active_target];
    uint32_t state=0x6e624eb7u ^ batch;
    for (size_t i=0; i<c->number_measurements; ++i) {
        state=state*1664525u+1013904223u;
        classes[i]=(uint8_t)(state>>31);
        memset(data+i*c->chunk_size, classes[i] ? 0xcc :
               (active_target==0 || active_target==3 || active_target==4) ? 0 : active_target==5 ? 0xaa : active_target==1 ? 0xbb : 0x42, c->chunk_size);
    }
#else
    original_prepare_inputs(c, data, classes);
#endif
    if (active_target<0) return;
    unsigned b=batches[active_target]++;
    assign(c, data, classes, b);
    prepared_counts[active_target]+=signal_size;
    if (signal_output) {
        uint64_t header[5]={(uint64_t)active_target,b,signal_size,signal_stride,signal_profile};
        save_bytes(header,sizeof header); save_bytes(classes,signal_size);
        save_bytes(data,signal_size*signal_stride); save_bytes(signal_counts,signal_size*4);
        dudect_require(fflush(signal_output)==0,"signal sidecar flush");
    }
    fprintf(stderr,"SENSITIVITY_FRAME {\"target\":%d,\"batch\":%u,\"samples\":%zu,\"profile\":%u}\n",
            active_target,b,signal_size,signal_profile);
}
uint8_t do_one_computation(uint8_t *data) {
    uint8_t result=base_computation(data);
    if (active_target>=0) {
        size_t offset=(size_t)(data-signal_base);
        dudect_require(offset%signal_stride==0 && offset/signal_stride<signal_size,
                       "signal callback sample correspondence");
        size_t i=offset/signal_stride;
        uint64_t work=signal_work(signal_counts[i]);
        __asm__ __volatile__("" : : "r"(work) : "memory");
        ++callback_counts[active_target];
#ifdef SENSITIVITY_FIXTURE
        uint32_t hash=((uint32_t)i*2654435761u) ^ (active_batch*2246822519u);
        unsigned noise=(hash>>12)%1000;
        uint64_t delta=(active_batch ? 50000 : 1000)+noise;
        if (active_batch && signal_profile==1 && noise<90) delta+=30*signal_labels[i];
        else delta+=200*enabled(signal_profile,active_batch,i,signal_labels);
        fixture_clock+=delta;
#endif
    }
    return result;
}
static void select_target(unsigned t) {
    current_test=(t==0 || t==3 || t==4) ? TEST_CT_EQ : t==5 ? TEST_SHA256 : t==1 ? TEST_HMAC_SHA256 : TEST_HMAC_SHA256_KEY;
}
static int signal_self_test(void) {
    uint8_t data[128*128], before[128*128], classes[128], labels_before[128];
    dudect_config_t c={.chunk_size=32,.number_measurements=128};
    uint64_t checked=0;
    for (unsigned t=0;t<6;++t) {
        active_target=t; select_target(t); c.chunk_size=target_stride(t);
        memset(data,0xa5,sizeof data);
        for (unsigned i=0;i<128;++i) {
            classes[i]=(i*37u+i/3)&1u;
            memset(data+i*c.chunk_size,classes[i] ? 0xcc : (t==0 || t==3 || t==4) ? 0 : t==5 ? 0xaa : t==1 ? 0xbb : 0x42,c.chunk_size);
        }
        memcpy(before,data,sizeof data); memcpy(labels_before,classes,sizeof classes);
        for (unsigned p=0;p<8;++p) for (unsigned b=0;b<17;++b) {
            signal_profile=p; assign(&c,data,classes,b);
            for (unsigned i=0;i<128;++i) {
                unsigned expected= b && classes[i] && (p==2 || (p==3 && b<=8) ||
                    (p==4 && b>=9) || (p==5 && b<=2) || (p==6 && b>=15) ||
                    (p==7 && i && classes[i-1]));
                dudect_require(signal_counts[i]==32+16*expected,"fixed signal assignment");
                dudect_require(signal_work(signal_counts[i])==signal_counts[i],"dependent iterations");
                uint8_t expected_result=base_computation(data+i*c.chunk_size);
                dudect_require(do_one_computation(data+i*c.chunk_size)==expected_result,"callback result");
                ++checked;
            }
        }
        dudect_require(!memcmp(data,before,sizeof data) && !memcmp(classes,labels_before,sizeof classes),
                       "signal mutated input or labels");
    }
    fprintf(stderr,"SENSITIVITY_SELF_TEST {\"checked\":%llu,\"timing\":false}\n",
            (unsigned long long)checked);
    return 0;
}
int main(int argc, char **argv) {
    aegaeon_crypto_init();
    memset(hmac_key,0x42,sizeof hmac_key); memset(key_test_message,0x5a,sizeof key_test_message);
    if (argc==2 && !strcmp(argv[1],"--signal-self-test")) return signal_self_test();
    const char *p=getenv("AEGAEON_SENSITIVITY_PROFILE");
    dudect_require(p!=NULL,"explicit sensitivity profile");
    for (signal_profile=0;signal_profile<8;++signal_profile)
        if (!strcmp(p,signal_names[signal_profile])) break;
    dudect_require(signal_profile<8,"unknown sensitivity profile");
#ifndef SENSITIVITY_FIXTURE
    dudect_require(signal_profile!=1,"C1 is synthetic only");
#endif
    int self=argc==2 && !strcmp(argv[1],"--self-test");
    if (!self) {
        const char *path=getenv("AEGAEON_SENSITIVITY_INPUTS");
        dudect_require(path!=NULL,"explicit sidecar path");
        signal_output=fopen(path,"wbx");
        save_bytes("AEGSEN04",8);
    }
    int status;
#ifdef SENSITIVITY_FIXTURE
    const char *name=getenv("AEGAEON_SENSITIVITY_TARGET");
    unsigned t;
    for (t=0;t<6;++t) if (name && !strcmp(name,target_names[t])) break;
    dudect_require(t<6,"explicit fixture target");
    select_target(t);
    status=dudect_run_case(target_names[t],target_stride(t),argc,argv);
#else
    status=original_harness_main(argc,argv);
#endif
    if (signal_output) {
        save_bytes("AEGSEND4",8);
        dudect_require(fclose(signal_output)==0,"sidecar completion"); signal_output=NULL;
    }
    for (unsigned t=0;t<6;++t) if (batches[t]) {
        if (!status && !self) dudect_require(batches[t]==17 && prepared_counts[t]==1114112 &&
                            callback_counts[t]==1114112,"full callback schedule");
        fprintf(stderr,"SENSITIVITY_COMPLETE {\"target\":%u,\"frames\":%u,\"prepared\":%llu,\"callbacks\":%llu}\n",
                t,batches[t],(unsigned long long)prepared_counts[t],(unsigned long long)callback_counts[t]);
    }
    return status;
}
