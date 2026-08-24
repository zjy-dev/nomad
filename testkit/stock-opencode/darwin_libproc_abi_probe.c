#include <stddef.h>
#include <stdio.h>
#include <mach/vm_prot.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/proc_info.h>

int main(void) {
  printf("proc_bsdinfo %zu %zu %zu %zu %zu %zu %zu\n",
         sizeof(struct proc_bsdinfo), offsetof(struct proc_bsdinfo, pbi_flags),
         offsetof(struct proc_bsdinfo, pbi_status),
         offsetof(struct proc_bsdinfo, pbi_pid),
         offsetof(struct proc_bsdinfo, pbi_ppid),
         offsetof(struct proc_bsdinfo, pbi_start_tvsec),
         offsetof(struct proc_bsdinfo, pbi_start_tvusec));
  printf("proc_regioninfo %zu %zu %zu %zu %zu\n",
         sizeof(struct proc_regioninfo),
         offsetof(struct proc_regioninfo, pri_protection),
         offsetof(struct proc_regioninfo, pri_offset),
         offsetof(struct proc_regioninfo, pri_address),
         offsetof(struct proc_regioninfo, pri_size));
  printf("vinfo_stat %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
         sizeof(struct vinfo_stat), offsetof(struct vinfo_stat, vst_dev),
         offsetof(struct vinfo_stat, vst_mode),
         offsetof(struct vinfo_stat, vst_ino),
         offsetof(struct vinfo_stat, vst_mtime),
         offsetof(struct vinfo_stat, vst_mtimensec),
         offsetof(struct vinfo_stat, vst_ctime),
         offsetof(struct vinfo_stat, vst_ctimensec),
         offsetof(struct vinfo_stat, vst_size),
         offsetof(struct vinfo_stat, vst_gen));
  printf("proc_regionwithpathinfo %zu %zu %zu %zu %zu\n",
         sizeof(struct proc_regionwithpathinfo),
         offsetof(struct proc_regionwithpathinfo, prp_prinfo),
         offsetof(struct proc_regionwithpathinfo, prp_vip),
         offsetof(struct proc_regionwithpathinfo, prp_vip.vip_vi.vi_stat),
         offsetof(struct proc_regionwithpathinfo, prp_vip.vip_path));
  printf("constants %d %d %d %d %d %d %d %d %d %d\n", PROC_PIDTBSDINFO,
         PROC_PIDREGIONPATHINFO, SIDL, SRUN, SSLEEP, SSTOP, SZOMB,
         PROC_FLAG_INEXIT, MAXPATHLEN, VM_PROT_EXECUTE);
  return 0;
}
