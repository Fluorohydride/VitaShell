OBJ_OUTPUT_DIR ?= obj
BIN_OUTPUT_DIR ?= bin

TITLE_ID	= VITASHELL
TARGET		= VitaShell
TARGET_VPK	= $(BIN_OUTPUT_DIR)/$(TARGET).vpk
TARGET_VELF	= $(BIN_OUTPUT_DIR)/$(TARGET).velf
TARGET_ELF	= $(BIN_OUTPUT_DIR)/$(TARGET).elf
TARGET_EBOOT	= $(BIN_OUTPUT_DIR)/eboot.bin
TARGET_SFO	= $(BIN_OUTPUT_DIR)/param.sfo
GENOBJS		= main.o init.o io_process.o package_installer.o network_update.o context_menu.o archive.o photo.o file.o text.o hex.o sfo.o \
		  uncommon_dialog.o message_dialog.o ime_dialog.o config.o theme.o language.o utils.o sha1.o \
		  audioplayer.o vitatp.o minizip/unzip.o minizip/ioapi.o bm.o

RESOURCES_PNG	= resources/folder_icon.png resources/file_icon.png resources/archive_icon.png resources/image_icon.png \
  		  resources/audio_icon.png resources/sfo_icon.png resources/text_icon.png\
  		  resources/ftp.png resources/battery.png resources/battery_bar_green.png resources/battery_bar_red.png \
  		  resources/battery_bar_charge.png resources/headphone.png resources/audio_previous.png resources/audio_pause.png \
  		  resources/audio_play.png resources/audio_next.png
RESOURCES_TXT	= resources/theme.txt resources/colors.txt resources/english_us.txt resources/changeinfo.txt
RESOURCES_BIN	= resources/updater_eboot.bin resources/updater_param.bin
GENOBJS		+= $(RESOURCES_PNG:.png=.o) $(RESOURCES_TXT:.txt=.o) $(RESOURCES_BIN:.bin=.o)

OBJS		= $(addprefix $(OBJ_OUTPUT_DIR)/, $(GENOBJS))

LIBS		= -lftpvita -lvita2d -lpng -ljpeg -lz -lm -lc \
  		  -lSceAppMgr_stub -lSceAppUtil_stub -lSceCommonDialog_stub \
  		  -lSceCtrl_stub -lSceDisplay_stub -lSceGxm_stub -lSceIme_stub \
  		  -lSceHttp_stub -lSceKernel_stub -lSceNet_stub -lSceNetCtl_stub \
  		  -lSceSsl_stub -lSceSysmodule_stub -lScePower_stub -lScePgf_stub libpromoter/libScePromoterUtil_stub.a \
  		  -lSceAudio_stub -lSceAudiodec_stub -lSceTouch_stub

#NETDBG_IP ?= 192.168.1.50

ifdef NETDBG_IP
CFLAGS += -DNETDBG_ENABLE=1 -DNETDBG_IP="\"$(NETDBG_IP)\""
endif
ifdef NETDBG_PORT
CFLAGS += -DNETDBG_PORT=$(NETDBG_PORT)
endif

PREFIX   = arm-vita-eabi
CC       = $(PREFIX)-gcc
CXX      = $(PREFIX)-g++
CFLAGS   = -Wl,-q -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable
CXXFLAGS = $(CFLAGS) -std=c++11 -fno-rtti -fno-exceptions
ASFLAGS  = $(CFLAGS)

.PHONY: directories

all: directories $(TARGET_VPK)

$(TARGET_VPK): $(TARGET_EBOOT)
	vita-mksfoex -d PARENTAL_LEVEL=1 -s APP_VER=00.95 -s TITLE_ID=$(TITLE_ID) "$(TARGET)" $(TARGET_SFO)
	vita-pack-vpk -s $(TARGET_SFO) -b $(TARGET_EBOOT) \
		--add pkg/sce_sys/icon0.png=sce_sys/icon0.png \
		--add pkg/sce_sys/livearea/contents/bg.png=sce_sys/livearea/contents/bg.png \
		--add pkg/sce_sys/livearea/contents/startup.png=sce_sys/livearea/contents/startup.png \
		--add pkg/sce_sys/livearea/contents/template.xml=sce_sys/livearea/contents/template.xml \
		$(TARGET_VPK)

$(TARGET_EBOOT): $(TARGET_VELF)
	vita-make-fself $< $@

$(TARGET_VELF): $(TARGET_ELF)
	vita-elf-create $< $@ libpromoter/promoterutil.json

$(TARGET_ELF): $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

$(OBJ_OUTPUT_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
$(OBJ_OUTPUT_DIR)/%.o: %.png
	$(PREFIX)-ld -r -b binary -o $@ $<
$(OBJ_OUTPUT_DIR)/%.o: %.txt
	$(PREFIX)-ld -r -b binary -o $@ $<
$(OBJ_OUTPUT_DIR)/%.o: %.bin
	$(PREFIX)-ld -r -b binary -o $@ $<

directories:
	@mkdir -p $(OBJ_OUTPUT_DIR)/minizip 
	@mkdir -p $(OBJ_OUTPUT_DIR)/resources
	@mkdir -p $(BIN_OUTPUT_DIR)

clean:
	@rm -rf $(TARGET_VPK) $(TARGET_VELF) $(TARGET_ELF) $(TARGET_EBOOT) $(TARGET_SFO) $(OBJS)

vpksend: $(TARGET_VPK)
	curl -T $(TARGET_VPK) ftp://$(PSVITAIP):1337/ux0:/
	@echo "Sent."

send: $(TARGET_EBOOT)
	curl -T $(TARGET_EBOOT) ftp://$(PSVITAIP):1337/ux0:/app/$(TITLE_ID)/
	@echo "Sent."
