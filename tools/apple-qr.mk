# Shared fetch rule for the loader and real-kernel checkpoint builds only.
QR_DIR = build/applekernel/qr
$(QR_DIR)/qrcodegen.freestanding.c $(QR_DIR)/qrcodegen.h &: tools/fetch-apple-qr.py
	python3 -B tools/fetch-apple-qr.py
