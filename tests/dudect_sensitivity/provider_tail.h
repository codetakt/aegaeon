/* Original generation is called once, with unchanged RNG calls and bytes.
 * Metadata is prepared outside the timer and only for the message case. */
static uint64_t diagnostic_assign(dudect_config_t *c, uint8_t *data,
                                  uint8_t *classes, unsigned batch) {
    dudect_require(c->number_measurements <= 65536 && c->chunk_size == 32,
                   "diagnostic HMAC shape");
    diagnostic_base = data;
    unsigned enabled = diagnostic_enabled(batch);
    uint64_t signal_samples = 0;
    for (size_t i = 0; i < c->number_measurements; ++i) {
        diagnostic_counts[i] = 32 + 16 * classes[i] * enabled;
        signal_samples += classes[i] * enabled;
    }
    return signal_samples;
}

void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    original_prepare_inputs(c, data, classes);
    if (current_test != TEST_HMAC_SHA256) return;
    uint64_t signal_samples = diagnostic_assign(c, data, classes, diagnostic_batch);
    fprintf(stderr, "HMAC_SIGNAL_FRAME {\"batch\":%u,\"samples\":%zu,"
            "\"signal_samples\":%llu,\"scope\":%u}\n", diagnostic_batch,
            c->number_measurements, (unsigned long long)signal_samples, diagnostic_scope);
    ++diagnostic_batch;
    diagnostic_prepared += c->number_measurements;
}

static int diagnostic_self_test(void) {
    uint8_t data[128*32], before[128*32], labels[128];
    uint64_t checked = 0;
    dudect_config_t config = {.chunk_size=32, .number_measurements=128};
    memset(hmac_key, 0x42, sizeof hmac_key);
    for (unsigned i=0; i<128; ++i) {
        labels[i] = (i*37u + i/3) & 1u;
        memset(data+i*32, labels[i] ? 0xcc : 0xbb, 32);
    }
    memcpy(before, data, sizeof data);
    diagnostic_base = data;
    for (unsigned scope=0; scope<3; ++scope) {
        diagnostic_scope=scope;
        for (unsigned batch=0; batch<17; ++batch) {
            unsigned expected_enabled = (scope==1 && batch>=1 && batch<=8) ||
                                        (scope==2 && batch>=9 && batch<=16);
            dudect_require(diagnostic_enabled(batch)==expected_enabled, "signal time assignment");
            uint64_t expected_samples = 0;
            uint64_t actual_samples = diagnostic_assign(&config, data, labels, batch);
            for (unsigned i=0; i<128; ++i) {
                expected_samples += labels[i]*expected_enabled;
                dudect_require(diagnostic_counts[i] == 32 + 16*labels[i]*expected_enabled,
                               "actual preparation assignment");
                dudect_require(diagnostic_work(diagnostic_counts[i])==diagnostic_counts[i],
                               "signal iteration count");
                uint8_t mac[32];
                real_hmac_sha256(hmac_key, 32, data+i*32, 32, mac);
                current_test=TEST_HMAC_SHA256;
                dudect_require(do_one_computation(data+i*32)==mac[0], "callback result changed");
                ++checked;
            }
            dudect_require(actual_samples==expected_samples,"signal population receipt");
        }
    }
    dudect_require(!memcmp(data,before,sizeof data), "input mutation");
    fprintf(stderr,"HMAC_SIGNAL_SELF_TEST {\"samples\":%llu,\"timing\":false}\n",
            (unsigned long long)checked);
    return 0;
}

int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--signal-self-test")) {
        aegaeon_crypto_init();
        return diagnostic_self_test();
    }
    const char *scope=getenv("AEGAEON_HMAC_SIGNAL_SCOPE");
    dudect_require(scope != NULL, "explicit diagnostic scope required");
    if (!strcmp(scope,"zero")) diagnostic_scope=0;
    else if (!strcmp(scope,"early")) diagnostic_scope=1;
    else if (!strcmp(scope,"late")) diagnostic_scope=2;
    else dudect_require(0,"unreviewed diagnostic scope");
    fprintf(stderr,"HMAC_SIGNAL_CONFIG {\"schema\":1,\"base\":32,\"dose\":16,\"scope\":\"%s\"}\n",scope);
    int status = original_harness_main(argc, argv);
    if (!status && !(argc==2 && !strcmp(argv[1],"--self-test")))
        dudect_require(diagnostic_batch==17 && diagnostic_prepared==1114112,
                       "diagnostic full HMAC schedule");
    fprintf(stderr,"HMAC_SIGNAL_COMPLETE {\"frames\":%u,\"prepared\":%llu}\n",
            diagnostic_batch,(unsigned long long)diagnostic_prepared);
    return status;
}
