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
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xd29f8c93, "device_remove_file" },
	{ 0xf5f1d863, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd0d8621b, "strlen" },
	{ 0x77cb5806, "device_destroy" },
	{ 0x121a120e, "__register_chrdev" },
	{ 0x4e830a3e, "strnicmp" },
	{ 0x85df9b6c, "strsep" },
	{ 0xa90dd060, "nf_register_hook" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x11089ac7, "_ctype" },
	{ 0x70d1f8f3, "strncat" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xb0f2df0b, "device_create" },
	{ 0x61651be, "strcat" },
	{ 0x969391b7, "device_create_file" },
	{ 0x738803e6, "strnlen" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x5656eb99, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0xa4f1a10f, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0xf9e73082, "scnprintf" },
	{ 0xaf243a97, "class_destroy" },
	{ 0xa55d174, "__class_create" },
	{ 0x5980dd50, "skb_copy_bits" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "E94086D66C0C6DE81B8D7BC");
