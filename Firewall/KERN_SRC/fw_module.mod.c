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
	{ 0xa4f1a10f, "nf_unregister_hook" },
	{ 0xa90dd060, "nf_register_hook" },
	{ 0xaf243a97, "class_destroy" },
	{ 0xa55d174, "__class_create" },
	{ 0xd29f8c93, "device_remove_file" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x77cb5806, "device_destroy" },
	{ 0x969391b7, "device_create_file" },
	{ 0xb0f2df0b, "device_create" },
	{ 0x121a120e, "__register_chrdev" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x5656eb99, "kmem_cache_alloc_trace" },
	{ 0xf5f1d863, "kmalloc_caches" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x61651be, "strcat" },
	{ 0x4ea56f9, "_kstrtol" },
	{ 0x1b6314fd, "in_aton" },
	{ 0x85df9b6c, "strsep" },
	{ 0x349cba85, "strchr" },
	{ 0x91715312, "sprintf" },
	{ 0x2276db98, "kstrtoint" },
	{ 0x50eedeb8, "printk" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xf9e73082, "scnprintf" },
	{ 0x42224298, "sscanf" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "CB56B615592C7B5A0FE93CF");
