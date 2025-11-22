#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/io.h>       // memremap
#include <linux/slab.h>     // kmalloc/kfree
#include <linux/types.h>
#include <linux/minmax.h>   // min()
#include <asm/barrier.h>    // dsb()

#define DEVICE_NAME "my_kmod"
#define CLASS_NAME  "mykmod"

// --- IOCTL Definitions ---
#define MY_KMOD_MAGIC 'k'

struct dma_transfer_args {
    phys_addr_t   pa;     // 目標物理位址
    size_t        len;    // 傳輸長度
    void __user  *data;   // 使用者空間資料指標
};

#define DMA_WRITE_PHYS _IOW(MY_KMOD_MAGIC, 1, struct dma_transfer_args)

static int my_major;
static struct class *my_class;
static struct device *my_device;

static char kbuf[128] = "hello from kernel";

/*
 * [關鍵函數] ARM64 Cache Flush
 * 用途：將 Cache 中的髒資料強制寫回 DRAM，並使 Cache 無效化。
 * 這是模擬 DMA 攻擊成功的關鍵，否則資料只會停留在 Kernel 的 Cache 中，TA 看不到。
 */
static void flush_dcache_range(void *vaddr, size_t size)
{
    unsigned long start = (unsigned long)vaddr;
    unsigned long end = start + size;
    unsigned long line_size;

    // 讀取 ARM64 dczid_el0 暫存器來取得 Cache Line 大小
    // Bits [3:0] contains log2(words in block) - 2
    asm volatile("mrs %0, dczid_el0" : "=r" (line_size));
    line_size = 4 << (line_size & 0xF); 

    // 對齊位址
    start = start & ~(line_size - 1);

    while (start < end) {
        // dc civac: Data Cache Clean and Invalidate by Virtual Address to Point of Coherency
        // 意思：把資料寫回 RAM，並且標記 Cache 為無效
        asm volatile("dc civac, %0" :: "r" (start) : "memory");
        start += line_size;
    }
    
    // 資料同步屏障，確保指令執行完畢
    asm volatile("dsb sy" ::: "memory");
}

/*
 * 處理 DMA 模擬寫入
 */
static int handle_dma_write_phys(struct dma_transfer_args *args)
{
    void *vaddr = NULL;
    void *data_buf = NULL;
    u8   *verify_buf = NULL;
    int ret = 0;
    size_t dump_len;

    // 1. 檢查參數
    if (!args->len || args->len > 1024 * 1024) {
        pr_err("my_kmod: invalid transfer length: %zu\n", args->len);
        return -EINVAL;
    }

    // 2. 準備 Kernel Buffer
    data_buf = kmalloc(args->len, GFP_KERNEL);
    if (!data_buf) {
        pr_err("my_kmod: failed to alloc data_buf\n");
        return -ENOMEM;
    }

    if (copy_from_user(data_buf, args->data, args->len)) {
        pr_err("my_kmod: copy_from_user(data) failed\n");
        ret = -EFAULT;
        goto out_free_data;
    }

    pr_info("my_kmod: DMA simulation request: %zu bytes to PA 0x%llx\n",
            args->len, (unsigned long long)args->pa);

    // 3. 映射物理記憶體 (System RAM)
    // 優先嘗試 MEMREMAP_WT (Write-Through)，這樣寫入會直通 DRAM
    vaddr = memremap(args->pa, args->len, MEMREMAP_WT);
    if (!vaddr) {
        // 如果不支援 WT，退回到 MEMREMAP_WB (Write-Back)
        // 雖然是 Cacheable，但我們會用 flush_dcache_range 手動同步
        vaddr = memremap(args->pa, args->len, MEMREMAP_WB);
    }

    if (!vaddr) {
        pr_err("my_kmod: memremap(0x%llx, %zu) failed\n",
               (unsigned long long)args->pa, args->len);
        ret = -ENOMEM;
        goto out_free_data;
    }

    // 4. 讀取目前內容 (驗證用)
    dump_len = min(args->len, (size_t)32);
    verify_buf = kmalloc(dump_len, GFP_KERNEL);
    if (!verify_buf) {
        pr_err("my_kmod: failed to alloc verify_buf\n");
        ret = -ENOMEM;
        goto out_unmap;
    }

    memcpy(verify_buf, vaddr, dump_len);
    print_hex_dump(KERN_INFO, "my_kmod: BEFORE DMA  ", DUMP_PREFIX_OFFSET,
                   16, 1, verify_buf, dump_len, false);

    // 5. 執行寫入 (模擬 DMA)
    print_hex_dump(KERN_INFO, "my_kmod: PAYLOAD      ", DUMP_PREFIX_OFFSET,
                   16, 1, data_buf, dump_len, false);

    memcpy(vaddr, data_buf, args->len);

    // [關鍵步驟] 強制將 Cache 寫回 DRAM
    flush_dcache_range(vaddr, args->len);
    pr_info("my_kmod: Cache flushed to DRAM (simulating DMA completion).\n");

    // 6. 再次讀取確認 (Kernel 觀點)
    // 這裡讀到的一定是新的，因為我們剛寫入且 flush 了
    memcpy(verify_buf, vaddr, dump_len);
    print_hex_dump(KERN_INFO, "my_kmod: AFTER DMA    ", DUMP_PREFIX_OFFSET,
                   16, 1, verify_buf, dump_len, false);

    pr_info("my_kmod: DMA write simulation completed.\n");

out_unmap:
    if (vaddr)
        memunmap(vaddr); // 釋放 memremap
    kfree(verify_buf);
out_free_data:
    kfree(data_buf);
    return ret;
}

/* ioctl */
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct dma_transfer_args args;
    int ret;

    switch (cmd) {
    case DMA_WRITE_PHYS:
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
            pr_err("my_kmod: copy_from_user(args) failed\n");
            return -EFAULT;
        }
        ret = handle_dma_write_phys(&args);
        break;

    default:
        pr_info("my_kmod: unknown ioctl cmd\n");
        ret = -ENOTTY;
        break;
    }

    return ret;
}

/* read */
static ssize_t my_read(struct file *file, char __user *buf,
                       size_t len, loff_t *offset)
{
    return simple_read_from_buffer(buf, len, offset, kbuf, strlen(kbuf));
}

/* write */
static ssize_t my_write(struct file *file, const char __user *buf,
                        size_t len, loff_t *offset)
{
    if (len > sizeof(kbuf) - 1)
        len = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, len))
        return -EFAULT;

    kbuf[len] = '\0';
    pr_info("my_kmod: write received: %s\n", kbuf);

    return len;
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = my_ioctl,
    .read           = my_read,
    .write          = my_write,
};

static int __init my_init(void)
{
    my_major = register_chrdev(0, DEVICE_NAME, &fops);
    if (my_major < 0) {
        pr_err("my_kmod: failed to register chrdev\n");
        return my_major;
    }

    my_class = class_create(CLASS_NAME);
    if (IS_ERR(my_class)) {
        unregister_chrdev(my_major, DEVICE_NAME);
        return PTR_ERR(my_class);
    }

    my_device = device_create(my_class, NULL, MKDEV(my_major, 0),
                              NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        class_destroy(my_class);
        unregister_chrdev(my_major, DEVICE_NAME);
        return PTR_ERR(my_device);
    }

    pr_info("my_kmod: loaded (major=%d)\n", my_major);
    return 0;
}

static void __exit my_exit(void)
{
    device_destroy(my_class, MKDEV(my_major, 0));
    class_destroy(my_class);
    unregister_chrdev(my_major, DEVICE_NAME);
    pr_info("my_kmod: unloaded\n");
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel module to simulate DMA write to physical address (with Cache Flush)");
MODULE_AUTHOR("Researcher");