#include "boost/array.hpp"
#include "boost/numeric/odeint.hpp"
// extern "C"{
// #include "cprintf.h"
// }

using namespace std;
using namespace boost::numeric::odeint;

const double sigma = 10.;
const double R = 28.0;
const double b = 8.0/3.0;

typedef boost::array< double , 3 > state_type;


void lorenz( const state_type &x , state_type &dxdt , double t )
{
    dxdt[0] = sigma * ( x[1] - x[0] );
    dxdt[1] = R * x[0] - x[1] - x[0] * x[2];
    dxdt[2] = -b * x[2] + x[0] * x[1];
}

void write_lorenz( const state_type &x , const double t )
{
    printf("%lf\t%.15lf\t%.15lf\t%.15lf\n", t, x[0], x[1], x[2]);
//    cout << t << '\t' << x[0] << '\t' << x[1] << '\t' << x[2] << endl;
}

int main(int argc, char **argv)
{
    state_type x = {12.013213, 1.742342, 0.034234}; // initial conditions
    runge_kutta_dopri5< state_type > stepper;
    double dt = 0.005;
    integrate_n_steps( stepper , lorenz , x , 0.0 , dt , 250/dt , write_lorenz ) ;
    //integrate( lorenz , x , 0.0 , 25.0, 0.000001 , write_lorenz );
}
