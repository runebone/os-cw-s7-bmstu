#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Runov Konstantin");
MODULE_DESCRIPTION("Memory Allocation Monitoring Module");

#define PROC_FILENAME "mem_monitor"
#define FUNC_NAME_LEN 128
#define CACHE_NAME_LEN 128
#define MAX_ENTRIES 10000

static DEFINE_SPINLOCK(mem_lock);
static int entry_count = 0;

struct mem_alloc_entry {
    pid_t pid;
    char func_name[FUNC_NAME_LEN];
    char comm[TASK_COMM_LEN];
    char cache_name[CACHE_NAME_LEN];
    char is_cache;
    size_t size;
    struct list_head list;
};

static LIST_HEAD(mem_alloc_list);

static void prune_oldest_entry(void)
{
    struct mem_alloc_entry *oldest;

    if (entry_count < MAX_ENTRIES)
        return;

    oldest = list_first_entry(&mem_alloc_list, struct mem_alloc_entry, list);
    list_del(&oldest->list);
    kfree(oldest);
    entry_count--;
}

static int pre_kmalloc_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = current;
    size_t size = regs->di;
    struct mem_alloc_entry *entry;

    if (size == 0)
        return 0;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return 0;

    strncpy(entry->func_name, "kmalloc", FUNC_NAME_LEN);
    entry->pid = task->pid;
    strncpy(entry->comm, task->comm, TASK_COMM_LEN);
    entry->size = size;
    entry->is_cache = 0;

    spin_lock(&mem_lock);
    prune_oldest_entry();
    list_add_tail(&entry->list, &mem_alloc_list);
    entry_count++;
    spin_unlock(&mem_lock);

    return 0;
}

static int pre_kmem_cache_alloc_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *cachep = (void *)regs->di;
    const char **name_ptr;
    const char *cache_name;
    struct task_struct *task = current;

    if (!cachep)
        return 0;

    name_ptr = (const char **)((char *)cachep + 96);
    if (!name_ptr)
        return 0;

    cache_name = *name_ptr;
    if (!cache_name)
        return 0;

    size_t cache_size = (size_t)(*((char *)cachep + 24));
    if (!cache_size)
        return 0;

    struct mem_alloc_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return 0;

    strncpy(entry->func_name, "kmem_cache_alloc", FUNC_NAME_LEN);
    entry->pid = task->pid;
    strncpy(entry->comm, task->comm, TASK_COMM_LEN);
    strncpy(entry->cache_name, cache_name, CACHE_NAME_LEN);
    entry->size = cache_size;
    entry->is_cache = 1;

    spin_lock(&mem_lock);
    prune_oldest_entry();
    list_add_tail(&entry->list, &mem_alloc_list);
    entry_count++;
    spin_unlock(&mem_lock);

    return 0;
}

static struct kprobe kp_kmalloc = {
    .symbol_name = "__kmalloc",
    .pre_handler = pre_kmalloc_handler,
};

static struct kprobe kp_kmem_cache_alloc = {
    .symbol_name = "kmem_cache_alloc",
    .pre_handler = pre_kmem_cache_alloc_handler,
};

static int mem_proc_show(struct seq_file *m, void *v)
{
    struct mem_alloc_entry *entry;

    spin_lock(&mem_lock);
    list_for_each_entry(entry, &mem_alloc_list, list) {
        if (entry->is_cache) {
            seq_printf(m, "[%s]: Process '%s' with PID %d allocated %zu bytes in cache '%s'\n",
                       entry->func_name, entry->comm, entry->pid, entry->size, entry->cache_name);
        } else {
            seq_printf(m, "[%s]: Process '%s' with PID %d allocated %zu bytes\n",
                       entry->func_name, entry->comm, entry->pid, entry->size);
        }
    }
    spin_unlock(&mem_lock);

    return 0;
}

static int mem_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, mem_proc_show, NULL);
}

static const struct proc_ops mem_proc_ops = {
    .proc_open = mem_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init mem_monitor_init(void)
{
    int ret;

    ret = register_kprobe(&kp_kmalloc);
    if (ret < 0)
        goto kmalloc_error;

    ret = register_kprobe(&kp_kmem_cache_alloc);
    if (ret < 0)
        goto kmem_cache_alloc_error;

    goto ok;

kmem_cache_alloc_error:
    unregister_kprobe(&kp_kmalloc);
kmalloc_error:
    return ret;

ok:
    proc_create(PROC_FILENAME, 0444, NULL, &mem_proc_ops);
    pr_info("Memory monitor module loaded.\n");
    return 0;
}

static void __exit mem_monitor_exit(void)
{
    struct mem_alloc_entry *entry, *tmp;

    unregister_kprobe(&kp_kmalloc);
    unregister_kprobe(&kp_kmem_cache_alloc);
    remove_proc_entry(PROC_FILENAME, NULL);

    spin_lock(&mem_lock);
    list_for_each_entry_safe(entry, tmp, &mem_alloc_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&mem_lock);

    pr_info("Memory monitor module unloaded.\n");
}

module_init(mem_monitor_init);
module_exit(mem_monitor_exit);
