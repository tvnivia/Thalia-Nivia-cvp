package co.gov.cajaviviendapopular.inventoryservice.model;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;

import java.math.BigDecimal;

@Data
@Entity
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Product {

    @Id
    private String name;

    private String description;

    private BigDecimal price;

    private Integer quantity;


}