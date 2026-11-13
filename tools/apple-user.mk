# Shared by the outer bridge and recursive real-kernel build.
USER_DIR = build/appleuser
.PHONY: user-layout
user-layout: $(USER_DIR)/apple_user_layout.h
$(USER_DIR)/user.o: kernel/arch/arm64/apple/user_test.S
	mkdir -p $(USER_DIR)
	aarch64-linux-gnu-gcc -c -ffreestanding -nostdlib $< -o $@
$(USER_DIR)/user.elf: $(USER_DIR)/user.o kernel/arch/arm64/apple/user.ld
	aarch64-linux-gnu-ld -T kernel/arch/arm64/apple/user.ld -nostdlib $< -o $@
$(USER_DIR)/apple_user_layout.h: $(USER_DIR)/user.elf tools/apple-user-layout.py
	python3 -B tools/apple-user-layout.py $(USER_DIR)
