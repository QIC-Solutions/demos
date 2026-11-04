//! Motor de conciliación: cruza los extractos del banco con los cobros de la
//! pasarela y los pagos a proveedores, cada noche.

mod canal;
mod extractos;
mod firma;

fn main() {
    let clave = firma::clave_informes();
    let _ = firma::firmar_informe(&clave, b"informe de conciliacion");
    let _ = canal::conector_banco();
}
