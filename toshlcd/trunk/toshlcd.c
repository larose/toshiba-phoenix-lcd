/**********************************************************************
 *
 * toshlcd.c -- Linux kernel module to change the lcd brightness of 
 * Toshiba Satellite Pro A100 with Phoenix BIOS.
 *
 * Copyright (C) 2007  Mathieu Larose <mathieu@mathieularose.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 **********************************************************************/



#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROCFS_MAX_SIZE     2
#define PROCFS_NAME         "toshlcd"
#define LCD_MIN_VALUE       48 //ascii code
#define LCD_MAX_VALUE       55 //ascii code
#define INVALID_VALUE       -1

static char * g_ptr;
static struct proc_dir_entry *g_proc_file;
static char lcd = LCD_MAX_VALUE;

module_param(lcd, byte, 0);
MODULE_PARM_DESC(lcd, "Lcd value (0..7)");

int init_module(void);
void cleanup_module(void);
int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data);
int procfile_write( struct file *file, const char *buffer, unsigned long buffer_size, void *data );
void set_lcd_brightness(char lcd_value);


int init_module()
{
    g_proc_file = create_proc_entry(PROCFS_NAME, S_IRUGO | S_IWUGO, NULL);
    
    if( g_proc_file == NULL )
    {
        remove_proc_entry(PROCFS_NAME, &proc_root);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    g_proc_file->read_proc  = procfile_read;
    g_proc_file->write_proc = procfile_write;
    g_proc_file->owner      = THIS_MODULE;
    
    g_ptr=(char *)kmalloc(100, GFP_KERNEL);

    if( lcd == INVALID_VALUE )
    {
        lcd = LCD_MAX_VALUE;
    }
    else
    {
        lcd += 48; // number to ascii
        if( !(lcd >= LCD_MIN_VALUE && lcd <= LCD_MAX_VALUE) )
        {
            lcd = LCD_MAX_VALUE;
        }
    }

    set_lcd_brightness(lcd);
    
    return 0;
}

void cleanup_module()
{
    kfree(g_ptr);
    remove_proc_entry(PROCFS_NAME, &proc_root);
}

int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
    char temp[2];
    int len = 0;

    if( offset > 0 )
        return 0;

    temp[0] = lcd;
    temp[1] = 0;
    
    len = sprintf(buffer, "%s\n",temp);
    return len;
}

int procfile_write( struct file *file, const char *buffer, unsigned long buffer_size, void *data )
{
    char temp_buffer[PROCFS_MAX_SIZE];
    
    if( buffer_size < PROCFS_MAX_SIZE || copy_from_user(temp_buffer, buffer, (int)PROCFS_MAX_SIZE) )
        return -EFAULT;
    
    set_lcd_brightness( temp_buffer[0] );
    return buffer_size;
}

void set_lcd_brightness(char lcd_value)
{
    char * addr;
    
    if( !(lcd_value >= LCD_MIN_VALUE && lcd_value <= LCD_MAX_VALUE) )
        return;

    lcd = lcd_value;
    
    addr = (char *)__pa(g_ptr);
    addr += 0x10;
    strcpy(g_ptr, "INVTOS");
    *(g_ptr+16) = (char)(lcd_value-0x30);
    
    __asm__("cli\n"		
	    "mov %0, %%edx\n"
	    "mov %%edx, %%edi\n"
	    "mov $0x20, %%ecx\n"
	    "mov $0x8000f840, %%eax\n mov $0xcf8, %%edx\n out %%eax, %%dx\n"
	    "mov $0xcfc, %%dx\n"
	    "in %%dx, %%eax\n"
	    "and $0x0000ff80, %%eax\n"
	    "add $0x2c, %%eax\n"
	    "mov %%ax, %%dx\n"
	    "in %%dx, %%eax\n"
	    "push %%eax\n"
	    "xor %%eax, %%eax\n"
	    "out %%eax, %%dx\n"
	    "mov $0xA2E4, %%eax\n"
	    "mov $0xb2, %%dx\n"
	    "out %%eax, %%dx\n"
	    "pop %%eax\n"
	    "mov $0x102c, %%dx\n"
	    "out %%eax, %%dx\n"       :
	    :"r"(addr): "%eax", "%edx", "%ecx","%edi", "%esi");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathieu Larose <mathieu@mathieularose.com>");
MODULE_DESCRIPTION("This module is intended to change the lcd brightness of Toshiba Satellite Pro A100 with Phoenix BIOS.");
