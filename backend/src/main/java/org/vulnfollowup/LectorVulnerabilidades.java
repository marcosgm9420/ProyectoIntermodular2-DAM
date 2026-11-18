
package org.vulnfollowup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.Set;

public class LectorVulnerabilidades {

    private static final Set<String> ESTADOS_VALIDOS = Set.of(
            "ABIERTA",
            "PENDIENTE DE REMEDIACIÓN",
            "RESUELTA",
            "CERRADA"
    );

    public static void main(String[] args) {

        ObjectMapper mapper = new ObjectMapper();

        try (InputStream archivo = LectorVulnerabilidades.class
                .getClassLoader()
                .getResourceAsStream("vulnerabilidades.json")) {

            if (archivo == null) {
                System.out.println("No se encuentra el fichero JSON.");
                return;
            }

            JsonNode vulnerabilidades = mapper.readTree(archivo);

            if (!vulnerabilidades.isArray()) {
                System.out.println("Error: el JSON debe contener una lista.");
                return;
            }

            int correctas = 0;
            int errores = 0;

            System.out.println("=== VULNERABILIDADES ===");

            for (JsonNode v : vulnerabilidades) {

                if (validar(v)) {

                    correctas++;

                    System.out.println(
                            v.get("identificador").asText()
                                    + " | "
                                    + v.get("descripcion").asText()
                                    + " | CVSS: "
                                    + v.get("puntuacionBase").asDouble()
                    );

                } else {

                    errores++;
                    System.out.println("Registro incorrecto: " + v);
                }
            }

            System.out.println("\n=== RESUMEN ===");
            System.out.println("Total: " + vulnerabilidades.size());
            System.out.println("Correctas: " + correctas);
            System.out.println("Errores: " + errores);

            if (vulnerabilidades.size() < 20) {
                System.out.println("AVISO: se necesitan al menos 20 registros.");
            }

        } catch (Exception e) {

            System.out.println("Error al leer el JSON: " + e.getMessage());
        }
    }

    private static boolean validar(JsonNode v) {

        String[] campos = {
                "identificador",
                "descripcion",
                "activoAfectado",
                "versionCVSS",
                "vectorBase",
                "estadoInicial"
        };

        for (String campo : campos) {

            if (!v.hasNonNull(campo)
                    || !v.get(campo).isTextual()
                    || v.get(campo).asText().isBlank()) {
                return false;
            }
        }

        if (!v.hasNonNull("puntuacionBase")
                || !v.get("puntuacionBase").isNumber()) {
            return false;
        }

        String version = v.get("versionCVSS").asText();
        String vector = v.get("vectorBase").asText();
        double puntuacion = v.get("puntuacionBase").asDouble();
        String estado = v.get("estadoInicial").asText();

        if (!version.equals("3.1") && !version.equals("4.0")) {
            return false;
        }

        if (!vector.startsWith("CVSS:" + version + "/")) {
            return false;
        }

        if (puntuacion < 0 || puntuacion > 10) {
            return false;
        }

        return ESTADOS_VALIDOS.contains(estado);
    }
}
