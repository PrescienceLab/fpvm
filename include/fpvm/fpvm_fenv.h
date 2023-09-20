#include <fenv.h>

extern int (*orig_feenableexcept)(int);
extern int (*orig_fedisableexcept)(int);
extern int (*orig_fegetexcept)();
extern int (*orig_feclearexcept)(int);
extern int (*orig_fegetexceptflag)(fexcept_t *flagp, int excepts);
extern int (*orig_feraiseexcept)(int excepts); 
extern int (*orig_fesetexceptflag)(const fexcept_t *flagp, int excepts);
extern int (*orig_fetestexcept)(int excepts);
extern int (*orig_fegetround)(void);
extern int (*orig_fesetround)(int rounding_mode);
extern int (*orig_fegetenv)(fenv_t *envp);
extern int (*orig_feholdexcept)(fenv_t *envp);
extern int (*orig_fesetenv)(const fenv_t *envp);
extern int (*orig_feupdateenv)(const fenv_t *envp);

