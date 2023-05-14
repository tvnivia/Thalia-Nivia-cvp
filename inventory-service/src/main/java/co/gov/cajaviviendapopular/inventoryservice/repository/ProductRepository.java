package co.gov.cajaviviendapopular.inventoryservice.repository;

import co.gov.cajaviviendapopular.inventoryservice.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProductRepository extends JpaRepository<Product, String> {

    List<Product> findAll();

}