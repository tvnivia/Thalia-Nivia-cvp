package co.gov.cajaviviendapopular.inventoryservice.repository;

import co.gov.cajaviviendapopular.inventoryservice.model.Purchase;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PurchaseRepository extends JpaRepository<Purchase, String> {

}
