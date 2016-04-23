#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2eae046e, "module_layout" },
	{ 0xa55d174, "__class_create" },
	{ 0x7d93eaac, "remove_rules_device" },
	{ 0xaf243a97, "class_destroy" },
	{ 0xa4f1a10f, "nf_unregister_hook" },
	{ 0xa90dd060, "nf_register_hook" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=fw";


MODULE_INFO(srcversion, "52E3B45C64A6D6DAC9A4574");
