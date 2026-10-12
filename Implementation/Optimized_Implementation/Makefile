.DEFAULT_GOAL := all
HASH_BACKEND ?= sm3
KNOWN_INSTANCES := GreatWall128f GreatWall128s GreatWall160f GreatWall160s \
	GreatWall192f GreatWall192s GreatWall256f GreatWall256s GreatWall512f GreatWall512s
INSTANCES ?= $(KNOWN_INSTANCES)

ifneq ($(filter-out $(KNOWN_INSTANCES),$(INSTANCES)),)
$(error INSTANCES contains an unsupported instance)
endif
ifeq ($(strip $(INSTANCES)),)
$(error INSTANCES must not be empty)
endif

INSTANCE_TARGETS := $(filter all KAT_SIG bench_sig clean,$(MAKECMDGOALS))
ifeq ($(strip $(INSTANCE_TARGETS)),)
INSTANCE_TARGETS := all
endif
ifneq ($(filter clean,$(INSTANCE_TARGETS)),)
ifneq ($(filter-out clean,$(INSTANCE_TARGETS)),)
$(error Run clean separately from build targets)
endif
endif

.PHONY: all KAT_SIG bench_sig clean $(INSTANCES)
all KAT_SIG bench_sig clean: $(INSTANCES)

$(INSTANCES):
	$(MAKE) -C "$@" HASH_BACKEND="$(HASH_BACKEND)" $(INSTANCE_TARGETS)

clean:
	rm -f -- .build-config *.o *.d *.a *.so *.so.* \
		KAT_SIG KAT_SIG.exe bench_sig bench_sig.exe \
		KAT_SIG_sm3_fixed KAT_SIG_deterministic bench_sig_deterministic
