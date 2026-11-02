/* Research artifact only. All six target cases share a fixed signal recipe.
 * Sidecar writes are outside the measured loop. The call counter and wrapper
 * are common to zero and signal arms; ordinary artifact equivalence is not
 * claimed. Source and resulting machine code are retained by build.py. */
static const char *signal_names[] = {"zero", "lower_tail", "full", "early_half",
    "late_half", "early_short", "late_short", "history"};
static unsigned signal_profile, batches[1], active_batch;
static int active_target = -1;
static uint8_t *signal_base, *signal_labels;
static size_t signal_size, signal_stride;
static uint32_t signal_counts[65536];
static uint64_t callback_counts[1], prepared_counts[1];
static FILE *signal_output;
static size_t target_stride(unsigned t) { (void)t; return 32; }
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
    dudect_require(active_target>=0 && active_target<1 &&
                   c->chunk_size==target_stride((unsigned)active_target) &&
                   c->number_measurements<=65536,
                   "compare signal shape");
    signal_base=data; signal_labels=classes; signal_size=c->number_measurements;
    active_batch=batch; signal_stride=c->chunk_size;
    for (size_t i=0; i<signal_size; ++i)
        signal_counts[i]=32+16*enabled(signal_profile, batch, i, classes);
}
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    active_target=0;
#ifdef SENSITIVITY_FIXTURE
    dudect_require(active_target>=0, "fixture target");
    unsigned batch=batches[active_target];
    uint32_t state=0x6e624eb7u ^ batch;
    for (size_t i=0; i<c->number_measurements; ++i) {
        state=state*1664525u+1013904223u;
        classes[i]=(uint8_t)(state>>31);
        memset(data+i*c->chunk_size,0,c->chunk_size);
        data[i*c->chunk_size]=classes[i];
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
        save_bytes(data,signal_size*signal_stride); save_bytes(secret,sizeof secret);
        for (uint32_t i=0;i<signal_size;++i) save_bytes(&i,sizeof i);
        save_bytes(signal_counts,signal_size*4);
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
static int signal_self_test(void) {
    uint8_t data[128*32], before[128*32], classes[128], labels_before[128];
    dudect_config_t c={.chunk_size=32,.number_measurements=128};
    uint64_t checked=0;
    /* Test original preparation and actual callback, including random labels. */
    original_prepare_inputs(&c,data,classes);
    for(unsigned i=0;i<128;++i) {
        dudect_require(classes[i]<=1 && data[i*32]==classes[i],"actual class operand");
        for(unsigned j=1;j<32;++j) dudect_require(data[i*32+j]==0,"actual operand tail");
        dudect_require(base_computation(data+i*32)==!classes[i],"original compare result");
    }
    memcpy(before,data,sizeof data); memcpy(labels_before,classes,sizeof classes);
    active_target=0;
    for(unsigned p=0;p<8;++p) for(unsigned b=0;b<17;++b) {
        signal_profile=p; assign(&c,data,classes,b);
        for(unsigned i=0;i<128;++i) {
            unsigned expected=b && classes[i] && (p==2 || (p==3 && b<=8) ||
                (p==4 && b>=9) || (p==5 && b<=2) || (p==6 && b>=15) ||
                (p==7 && i && classes[i-1]));
            dudect_require(signal_counts[i]==32+16*expected,"fixed signal assignment");
            dudect_require(signal_work(signal_counts[i])==signal_counts[i],"dependent iterations");
            dudect_require(do_one_computation(data+i*32)==!classes[i],"compare result");
            ++checked;
        }
    }
    dudect_require(!memcmp(data,before,sizeof data) && !memcmp(classes,labels_before,sizeof classes),"input mutated");
    fprintf(stderr,"COMPARE_SELF_TEST {\"checked\":%llu,\"timing\":false}\n",(unsigned long long)checked);
    return 0;
}
int main(int argc, char **argv) {
    if(argc==2 && !strcmp(argv[1],"--signal-self-test")) return signal_self_test();
    const char *p=getenv("AEGAEON_SENSITIVITY_PROFILE");
    dudect_require(p!=NULL,"explicit sensitivity profile");
    for(signal_profile=0;signal_profile<8;++signal_profile) if(!strcmp(p,signal_names[signal_profile])) break;
    dudect_require(signal_profile<8,"unknown profile");
#ifndef SENSITIVITY_FIXTURE
    dudect_require(signal_profile!=1,"C1 is synthetic only");
#endif
    int self=argc==2 && !strcmp(argv[1],"--self-test");
    if(!self) {
        const char *path=getenv("AEGAEON_SENSITIVITY_INPUTS");
        dudect_require(path!=NULL,"explicit sidecar");signal_output=fopen(path,"wbx");save_bytes("AEGCMP01",8);
    }
    /* Startup checks in the original main occur with active_target=-1. */
    int status=original_harness_main(argc,argv);
    if(signal_output) {save_bytes("AEGCEND1",8);dudect_require(fclose(signal_output)==0,"sidecar completion");}
    if(batches[0]) {
        if(!status && !self) dudect_require(batches[0]==17 && prepared_counts[0]==1114112 && callback_counts[0]==1114112,"full compare schedule");
        fprintf(stderr,"SENSITIVITY_COMPLETE {\"target\":0,\"frames\":%u,\"prepared\":%llu,\"callbacks\":%llu}\n",batches[0],(unsigned long long)prepared_counts[0],(unsigned long long)callback_counts[0]);
    }
    return status;
}
