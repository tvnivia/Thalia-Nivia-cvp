package co.gov.cajaviviendapopular.inventoryservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.GenericGenerator;

import java.math.BigDecimal;

@Data
@Entity
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Purchase {

    @Id
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid")
    private String id;

    @ManyToOne(targetEntity = Product.class, fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "name")
    private Product product;

    private Integer quantity;

    private BigDecimal totalPrice;
}