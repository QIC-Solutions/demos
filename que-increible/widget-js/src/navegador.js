// Lo que corre en el navegador de la tienda (empaquetado con el widget). Cifra
// el borrador del carrito con una frase de paso escrita aquí: se ve en el
// código fuente de cualquier página que incruste el widget.
import CryptoJS from 'crypto-js';

const FRASE = 'qic-demo-frase-del-widget';

export function guardarBorrador(carrito) {
  return CryptoJS.AES.encrypt(JSON.stringify(carrito), FRASE).toString();
}

export function firmaDelEvento(evento, secreto) {
  return CryptoJS.HmacSHA1(JSON.stringify(evento), secreto).toString(CryptoJS.enc.Base64);
}

export function idDeSesion(tienda, marca) {
  return CryptoJS.MD5(`${tienda}:${marca}`).toString();
}
